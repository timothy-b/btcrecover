from __future__ import print_function, absolute_import, division, unicode_literals

import hashlib
import math
import os
import struct
import sys
import time
import numpy
import pyopencl

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.btrcpass import mode
from btcrecover.utilities.safe_print import error_exit


@Wallet.register_wallet_class
class WalletArmory(object):
    program_name = os.path.basename(sys.argv[0])

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"ar"

    @staticmethod
    def passwords_per_seconds(seconds):
        return max(int(round(4 * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(0)
        return wallet_file.read(8) == b"\xbaWALLET\x00"  # Armory magic

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        self.load_armory_library()

    def __getstate__(self):
        # Extract data from unpicklable Armory library objects and delete them
        state = self.__dict__.copy()
        del state["_address"], state["_kdf"]
        state["addrStr20"]         = self._address.addrStr20
        state["binPrivKey32_Encr"] = self._address.binPrivKey32_Encr.toBinStr()
        state["binInitVect16"]     = self._address.binInitVect16.toBinStr()
        state["binPublicKey65"]    = self._address.binPublicKey65.toBinStr()
        state["memoryReqtBytes"]   = self._kdf.getMemoryReqtBytes()
        state["numIterations"]     = self._kdf.getNumIterations()
        state["salt"]              = self._kdf.getSalt().toBinStr()
        return state

    def __setstate__(self, state):
        # Restore unpicklable Armory library objects
        # global mode.tstr
        try:
            assert mode.tstr == str  # load_armory_library() requires this;
        except NameError:       # but mode.tstr doesn't exist when using multiprocessing on Windows
            mode.tstr = str          # so apply this workaround
        self.load_armory_library()
        #
        state["_address"] = PyBtcAddress().createFromEncryptedKeyData(
            state["addrStr20"],
            SecureBinaryData(state["binPrivKey32_Encr"]),
            SecureBinaryData(state["binInitVect16"]),
            pubKey=state["binPublicKey65"]  # optional; makes checking slightly faster
        )
        del state["addrStr20"],     state["binPrivKey32_Encr"]
        del state["binInitVect16"], state["binPublicKey65"]
        #
        state["_kdf"] = KdfRomix(
            state["memoryReqtBytes"],
            state["numIterations"],
            SecureBinaryData(state["salt"])
        )
        del state["memoryReqtBytes"], state["numIterations"], state["salt"]
        #
        self.__dict__ = state

    # Load the Armory wallet file
    @classmethod
    def load_from_filename(cls, wallet_filename, settings=None):
        self = cls(loading=True)
        wallet = PyBtcWallet().readWalletFile(wallet_filename)
        self._address = wallet.addrMap['ROOT']
        self._kdf     = wallet.kdf
        if not self._address.hasPrivKey():
            error_exit("Armory wallet cannot be watching-only")
        if not self._address.useEncryption :
            error_exit("Armory wallet is not encrypted")
        return self

    # Import an Armory private key that was extracted by extract-armory-privkey.py
    @classmethod
    def load_from_data_extract(cls, privkey_data):
        self = cls(loading=True)
        self._address = PyBtcAddress().createFromEncryptedKeyData(
            privkey_data[:20],                      # address (160 bit hash)
            SecureBinaryData(privkey_data[20:52]),  # encrypted private key
            SecureBinaryData(privkey_data[52:68])   # initialization vector
        )
        bytes_reqd, iter_count = struct.unpack(b"< I I", privkey_data[68:76])
        self._kdf = KdfRomix(bytes_reqd, iter_count, SecureBinaryData(privkey_data[76:]))  # kdf args and seed
        return self

    def difficulty_info(self):
        return "{:g} MiB, {} iterations + ECC".format(round(self._kdf.getMemoryReqtBytes() / 1024**2, 2), self._kdf.getNumIterations())

    # Defer to either the cpu or OpenCL implementation
    def return_verified_password_or_false(self, passwords):
        return self._return_verified_password_or_false_opencl(passwords) if hasattr(self, "_cl_devices") \
          else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords):
        for count, password in enumerate(passwords, 1):
            if self._address.verifyEncryptionKey(self._kdf.DeriveKey(SecureBinaryData(password))):
                return password, count
        else:
            return False, count

    # Load and initialize the OpenCL kernel for Armory, given the global wallet and these params:
    #   devices   - a list of one or more of the devices returned by get_opencl_devices()
    #   global_ws - a list of global work sizes, exactly one per device
    #   local_ws  - a list of local work sizes (or Nones), exactly one per device
    #   int_rate  - number of times to interrupt calculations to prevent hanging
    #               the GPU driver per call to return_verified_password_or_false()
    #   save_every- how frequently hashes are saved in the lookup table
    #   calc_memory-if true, just print the memory statistics and exit
    def init_opencl_kernel(self, devices, global_ws, local_ws, int_rate, save_every = 1, calc_memory = False):
        # Need to save these for return_verified_password_or_false_opencl()
        assert devices, "WalletArmory.init_opencl_kernel: at least one device is selected"
        assert len(devices) == len(global_ws) == len(local_ws), "WalletArmory.init_opencl_kernel: one global_ws and one local_ws specified for each device"
        assert save_every > 0
        self._cl_devices   = devices
        self._cl_global_ws = global_ws
        self._cl_local_ws  = local_ws

        self._cl_V_buffer0s = self._cl_V_buffer1s = self._cl_V_buffer2s = self._cl_V_buffer3s = None  # clear any
        self._cl_kernel = self._cl_kernel_fill = self._cl_queues = self._cl_hashes_buffers = None     # previously loaded
        cl_context = pyopencl.Context(devices)
        #
        # Load and compile the OpenCL program, passing in defines for SAVE_EVERY, V_LEN, and SALT
        assert  self._kdf.getMemoryReqtBytes() % 64 == 0
        v_len = self._kdf.getMemoryReqtBytes() // 64
        salt  = self._kdf.getSalt().toBinStr()
        assert len(salt) == 32
        with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), "romix-ar-kernel.cl")) as opencl_file:
            cl_program = pyopencl.Program(cl_context, opencl_file.read()).build(
                b"-w -D SAVE_EVERY={}U -D V_LEN={}U -D SALT0=0x{:016x}UL -D SALT1=0x{:016x}UL -D SALT2=0x{:016x}UL -D SALT3=0x{:016x}UL" \
                .format(save_every, v_len, *struct.unpack(b">4Q", salt)))
        #
        # Configure and store for later the OpenCL kernels (the entrance functions)
        self._cl_kernel_fill = cl_program.kernel_fill_V    # this kernel is executed first
        self._cl_kernel      = cl_program.kernel_lookup_V  # this kernel is executed once per iter_count
        self._cl_kernel_fill.set_scalar_arg_dtypes([None, None, None, None, numpy.uint32, numpy.uint32, None, numpy.uint8])
        self._cl_kernel     .set_scalar_arg_dtypes([None, None, None, None, numpy.uint32, None])
        #
        # Check the local_ws sizes
        for i, device in enumerate(devices):
            if local_ws[i] is None: continue
            max_local_ws = min(self._cl_kernel_fill.get_work_group_info(pyopencl.kernel_work_group_info.WORK_GROUP_SIZE, device),
                               self._cl_kernel     .get_work_group_info(pyopencl.kernel_work_group_info.WORK_GROUP_SIZE, device))
            if local_ws[i] > max_local_ws:
                error_exit("--local-ws of", local_ws[i], "exceeds max of", max_local_ws, "for GPU '"+device.name.strip()+"' with Armory wallets")

        if calc_memory:
            mem_per_worker = math.ceil(v_len / save_every) * 64 + 64
            print(    "Details for this wallet")
            print(    "  ROMix V-table length:  {:,}".format(v_len))
            print(    "  outer iteration count: {:,}".format(self._kdf.getNumIterations()))
            print(    "  with --mem-factor {},".format(save_every if save_every>1 else "1 (the default)"))
            print(    "    memory per global worker: {:,} KiB\n".format(int(round(mem_per_worker / 1024))))
            #
            for i, device in enumerate(devices):
                print("Details for", device.name.strip())
                print("  global memory size:     {:,} MiB".format(int(round(device.global_mem_size / float(1024**2)))))
                print("  with --mem-factor {},".format(save_every if save_every>1 else "1 (the default)"))
                print("    est. max --global-ws: {}".format((int(device.global_mem_size // mem_per_worker) // 32 * 32)))
                print("    with --global-ws {},".format(global_ws[i] if global_ws[i]!=4096 else "4096 (the default)"))
                print("      est. memory usage:  {:,} MiB\n".format(int(round(global_ws[i] * mem_per_worker / float(1024**2)))))
            sys.exit(0)

        # Create one command queue, one I/O buffer, and four "V" buffers per device
        self._cl_queues         = []
        self._cl_hashes_buffers = []
        self._cl_V_buffer0s     = []
        self._cl_V_buffer1s     = []
        self._cl_V_buffer2s     = []
        self._cl_V_buffer3s     = []
        for i, device in enumerate(devices):
            self._cl_queues.append(pyopencl.CommandQueue(cl_context, device))
            # Each I/O buffer is of len --global-ws * (size-of-sha512-hash-in-bytes == 512 bits / 8 == 64)
            self._cl_hashes_buffers.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, global_ws[i] * 64))
            #
            # The "V" buffers total v_len * 64 * --global-ws bytes per device. There are four
            # per device, so each is 1/4 of the total. They are reduced by a factor of save_every,
            # rounded up to the nearest 64-byte boundry (the size-of-sha512-hash-in-bytes)
            assert global_ws[i] % 4 == 0  # (kdf.getMemoryReqtBytes() is already checked to be divisible by 64)
            V_buffer_len = int(math.ceil(v_len / save_every)) * 64 * global_ws[i] // 4
            self._cl_V_buffer0s.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, V_buffer_len))
            self._cl_V_buffer1s.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, V_buffer_len))
            self._cl_V_buffer2s.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, V_buffer_len))
            self._cl_V_buffer3s.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, V_buffer_len))

        # Doing all the work at once will hang the GPU. One set of passwords requires iter_count
        # calls to cl_kernel_fill and to cl_kernel. Divide 2xint_rate among these calls (2x is
        # an arbitrary choice) and then calculate how much work (v_len_chunksize) to perform for
        # each call rounding up to to maximize the work done in the last sets to optimize performance.
        int_rate = int(round(int_rate / self._kdf.getNumIterations())) or 1  # there are two 2's which cancel out
        self._v_len_chunksize = v_len // int_rate or 1
        if self._v_len_chunksize % int_rate != 0:  # if not evenly divisible,
            self._v_len_chunksize += 1             # then round up.
        if self._v_len_chunksize % 2 != 0:         # also if not divisible by two,
            self._v_len_chunksize += 1             # make it divisible by two.

    def _return_verified_password_or_false_opencl(self, passwords):
        assert len(passwords) <= sum(self._cl_global_ws), "WalletArmory.return_verified_password_or_false_opencl: at most --global-ws passwords"

        # The first password hash is done by the CPU
        salt = self._kdf.getSalt().toBinStr()
        hashes = numpy.empty([sum(self._cl_global_ws), 64], numpy.uint8)
        for i, password in enumerate(passwords):
            hashes[i] = numpy.frombuffer(hashlib.sha512(password + salt).digest(), numpy.uint8)

        # Divide up and copy the starting hashes into the OpenCL buffer(s) (one per device) in parallel
        done   = []  # a list of OpenCL event objects
        offset = 0
        for devnum, ws in enumerate(self._cl_global_ws):
            done.append(pyopencl.enqueue_copy(self._cl_queues[devnum], self._cl_hashes_buffers[devnum],
                                              hashes[offset : offset + ws], is_blocking=False))
            self._cl_queues[devnum].flush()  # Starts the copy operation
            offset += ws
        pyopencl.wait_for_events(done)

        v_len = self._kdf.getMemoryReqtBytes() // 64
        for i in xrange(self._kdf.getNumIterations()):

            # Doing all the work at once will hang the GPU, so instead do v_len_chunksize chunks
            # at a time, pausing briefly while waiting for them to complete, and then continuing.
            # Because the work is probably not evenly divisible by v_len_chunksize, the loops below
            # perform all but the last of these v_len_chunksize sets of work.

            # The first set of kernel executions runs cl_kernel_fill which fills the "V" lookup table.

            v_start = -self._v_len_chunksize  # used if the loop below doesn't run (when --int-rate == 1)
            for v_start in xrange(0, v_len - self._v_len_chunksize, self._v_len_chunksize):
                done = []  # a list of OpenCL event objects
                # Start up a kernel for each device to do one chunk of v_len_chunksize work
                for devnum in xrange(len(self._cl_devices)):
                    done.append(self._cl_kernel_fill(
                        self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                        None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                        self._cl_V_buffer0s[devnum], self._cl_V_buffer1s[devnum], self._cl_V_buffer2s[devnum], self._cl_V_buffer3s[devnum],
                        v_start, self._v_len_chunksize, self._cl_hashes_buffers[devnum], 0 == v_start == i))
                    self._cl_queues[devnum].flush()  # Starts the kernel
                pyopencl.wait_for_events(done)

            # Perform the remaining work (usually less then v_len_chunksize)
            done = []  # a list of OpenCL event objects
            for devnum in xrange(len(self._cl_devices)):
                done.append(self._cl_kernel_fill(
                    self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                    None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                    self._cl_V_buffer0s[devnum], self._cl_V_buffer1s[devnum], self._cl_V_buffer2s[devnum], self._cl_V_buffer3s[devnum],
                    v_start + self._v_len_chunksize, v_len - self._v_len_chunksize - v_start, self._cl_hashes_buffers[devnum], v_start<0 and i==0))
                self._cl_queues[devnum].flush()  # Starts the kernel
            pyopencl.wait_for_events(done)

            # The second set of kernel executions runs cl_kernel which uses the "V" lookup table to complete
            # the hashes. This kernel runs with half the count of internal iterations as cl_kernel_fill.

            assert self._v_len_chunksize % 2 == 0
            v_start = -self._v_len_chunksize//2  # used if the loop below doesn't run (when --int-rate == 1)
            for v_start in xrange(0, v_len//2 - self._v_len_chunksize//2, self._v_len_chunksize//2):
                done = []  # a list of OpenCL event objects
                # Start up a kernel for each device to do one chunk of v_len_chunksize work
                for devnum in xrange(len(self._cl_devices)):
                    done.append(self._cl_kernel(
                        self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                        None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                        self._cl_V_buffer0s[devnum], self._cl_V_buffer1s[devnum], self._cl_V_buffer2s[devnum], self._cl_V_buffer3s[devnum],
                        self._v_len_chunksize//2, self._cl_hashes_buffers[devnum]))
                    self._cl_queues[devnum].flush()  # Starts the kernel
                pyopencl.wait_for_events(done)

            # Perform the remaining work (usually less then v_len_chunksize)
            done = []  # a list of OpenCL event objects
            for devnum in xrange(len(self._cl_devices)):
                done.append(self._cl_kernel(
                    self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                    None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                    self._cl_V_buffer0s[devnum], self._cl_V_buffer1s[devnum], self._cl_V_buffer2s[devnum], self._cl_V_buffer3s[devnum],
                    v_len//2 - self._v_len_chunksize//2 - v_start, self._cl_hashes_buffers[devnum]))
                self._cl_queues[devnum].flush()  # Starts the kernel
            pyopencl.wait_for_events(done)

        # Copy the resulting fully computed hashes back to RAM in parallel
        done   = []  # a list of OpenCL event objects
        offset = 0
        for devnum, ws in enumerate(self._cl_global_ws):
            done.append(pyopencl.enqueue_copy(self._cl_queues[devnum], hashes[offset : offset + ws],
                                              self._cl_hashes_buffers[devnum], is_blocking=False))
            offset += ws
            self._cl_queues[devnum].flush()  # Starts the copy operation
        pyopencl.wait_for_events(done)

        # The first 32 bytes of each computed hash is the derived key. Use each to try to decrypt the private key.
        for i, password in enumerate(passwords):
            if self._address.verifyEncryptionKey(hashes[i,:32].tostring()):
                return password, i + 1

        return False, i + 1

    # Try to add the Armory libraries to the path for various platforms
    is_armory_path_added = False

    @classmethod
    def add_armory_library_path(cls):
        if cls.is_armory_path_added:
            return
        if sys.platform == "win32":
            progfiles_path = os.environ.get("ProgramFiles",  r"C:\Program Files")  # default is for XP
            armory_path    = progfiles_path + r"\Armory"
            sys.path.extend((armory_path, armory_path + r"\library.zip"))
            # 64-bit Armory might install into the 32-bit directory; if this is 64-bit Python look in both
            if struct.calcsize(b"P") * 8 == 64:  # calcsize('P') is a pointer's size in bytes
                assert not progfiles_path.endswith("(x86)"), "ProgramFiles doesn't end with '(x86)' on x64 Python"
                progfiles_path += " (x86)"
                armory_path     = progfiles_path + r"\Armory"
                sys.path.extend((armory_path, armory_path + r"\library.zip"))
        elif sys.platform.startswith("linux"):
            sys.path.extend(("/usr/local/lib/armory", "/usr/lib/armory"))
        elif sys.platform == "darwin":
            import glob
            sys.path.extend((
                "/Applications/Armory.app/Contents/MacOS/py/usr/local/lib/armory",
                "/Applications/Armory.app/Contents/MacOS/py/usr/lib/armory",
                "/Applications/Armory.app/Contents/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages"))
            sys.path.extend(glob.iglob(
                "/Applications/Armory.app/Contents/Frameworks/Python.framework/Versions/2.7/lib/python2.7/site-packages/*.egg"))
        cls.is_armory_path_added = True

    is_armory_loaded = False

    @classmethod
    def load_armory_library(cls):
        if mode.tstr == unicode:
            error_exit("armory wallets do not support unicode; please remove the --utf8 option")

        if cls.is_armory_loaded:
            return

        # Temporarily blank out argv before importing Armory, otherwise it attempts to process argv,
        # and then add this one option to avoid a confusing warning message from Armory
        old_argv = sys.argv[1:]
        sys.argv[1:] = ["--language", "es"]

        WalletArmory.add_armory_library_path()
        try:
            # Try up to 10 times to load the first Armory library (there's a race
            # condition on opening an Armory log file in Windows when multiprocessing)
            import random
            for i in xrange(10):
                try:
                    from armoryengine.ArmoryUtils import getVersionInt, readVersionString, BTCARMORY_VERSION
                except IOError as e:
                    if i < 9 and e.filename.endswith(r"\armorylog.txt"):
                        time.sleep(random.uniform(0.05, 0.15))
                    else:
                        raise  # unexpected failure
                except SystemExit:
                    if len(sys.argv) == 3:
                        del sys.argv[1:]  # older versions of Armory don't support the --language option; remove it
                    else:
                        raise  # unexpected failure
                except ImportError as e:
                    if "not a valid Win32 application" in unicode(e):
                        print(cls.program_name + ": error: can't load Armory, 32/64 bit mismatch between it and Python", file=sys.stderr)
                    raise
                else:
                    break  # when it succeeds

            # Fixed https://github.com/etotheipi/BitcoinArmory/issues/196
            if getVersionInt(BTCARMORY_VERSION) < getVersionInt(readVersionString("0.92")):
                error_exit("Armory version 0.92 or greater is required")

            # These are the modules we actually need
            global PyBtcWallet, PyBtcAddress, SecureBinaryData, KdfRomix
            from armoryengine.PyBtcWallet import PyBtcWallet
            from armoryengine.PyBtcWallet import PyBtcAddress
            from CppBlockUtils import SecureBinaryData, KdfRomix
            cls.is_armory_loaded = True

        finally:
            sys.argv[1:] = old_argv  # restore the command line
