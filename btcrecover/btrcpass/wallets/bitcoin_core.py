from __future__ import print_function

import hashlib
import itertools
import os
import struct
import numpy
import pyopencl
import sys

from btcrecover.btrcpass.wallets.wallet import Wallet
from btcrecover.utilities.crypto_util import CryptoUtil
from btcrecover.btrcpass import mode
from btcrecover.utilities.safe_print import error_exit


@Wallet.register_wallet_class
class WalletBitcoinCore(object):
    program_name = os.path.basename(sys.argv[0])

    class __metaclass__(type):
        @property
        def data_extract_id(cls): return b"bc"

    @staticmethod
    def passwords_per_seconds(seconds):
        return max(int(round(10 * seconds)), 1)

    @staticmethod
    def is_wallet_file(wallet_file):
        wallet_file.seek(12)
        return wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00"  # BDB magic, Btree v9

    def __init__(self, loading = False):
        assert loading, 'use load_from_* to create a ' + self.__class__.__name__
        CryptoUtil.load_aes256_library()

    def __setstate__(self, state):
        # (re-)load the required libraries after being unpickled
        CryptoUtil.load_aes256_library(warnings=False)
        self.__dict__ = state

    # Load a Bitcoin Core BDB wallet file given the filename and extract part of the first encrypted master key
    @classmethod
    def load_from_filename(cls, wallet_filename, force_purepython=False, settings=None):
        if not force_purepython:
            try:
                import bsddb.db
            except ImportError:
                force_purepython = True

        if not force_purepython:
            db_env = bsddb.db.DBEnv()
            wallet_filename = os.path.abspath(wallet_filename)
            try:
                db_env.open(os.path.dirname(wallet_filename), bsddb.db.DB_CREATE | bsddb.db.DB_INIT_MPOOL)
                db = bsddb.db.DB(db_env)
                db.open(wallet_filename, b"main", bsddb.db.DB_BTREE, bsddb.db.DB_RDONLY)
            except UnicodeEncodeError:
                error_exit("the entire path and filename of Bitcoin Core wallets must be entirely ASCII")
            mkey = db.get(b"\x04mkey\x01\x00\x00\x00")
            db.close()
            db_env.close()

        else:
            def align_32bits(i):  # if not already at one, return the next 32-bit boundry
                m = i % 4
                return i if m == 0 else i + 4 - m

            with open(wallet_filename, "rb") as wallet_file:
                wallet_file.seek(12)
                assert wallet_file.read(8) == b"\x62\x31\x05\x00\x09\x00\x00\x00", "is a Btree v9 file"
                mkey = None

                # Don't actually try walking the btree, just look through every btree leaf page
                # for the value/key pair (yes they are in that order...) we're searching for
                wallet_file.seek(20)
                page_size        = struct.unpack(b"<I", wallet_file.read(4))[0]
                wallet_file_size = os.path.getsize(wallet_filename)
                for page_base in xrange(page_size, wallet_file_size, page_size):  # skip the header page
                    wallet_file.seek(page_base + 20)
                    (item_count, first_item_pos, btree_level, page_type) = struct.unpack(b"< H H B B", wallet_file.read(6))
                    if page_type != 5 or btree_level != 1:
                        continue  # skip non-btree and non-leaf pages
                    pos = align_32bits(page_base + first_item_pos)  # position of the first item
                    wallet_file.seek(pos)
                    for i in xrange(item_count):    # for each item in the current page
                        (item_len, item_type) = struct.unpack(b"< H B", wallet_file.read(3))
                        if item_type & ~0x80 == 1:  # if it's a variable-length key or value
                            if item_type == 1:      # if it's not marked as deleted
                                if i % 2 == 0:      # if it's a value, save it's position
                                    value_pos = pos + 3
                                    value_len = item_len
                                # else it's a key, check if it's the key we're looking for
                                elif item_len == 9 and wallet_file.read(item_len) == b"\x04mkey\x01\x00\x00\x00":
                                    wallet_file.seek(value_pos)
                                    mkey = wallet_file.read(value_len)  # found it!
                                    break
                            pos = align_32bits(pos + 3 + item_len)  # calc the position of the next item
                        else:
                            pos += 12  # the two other item types have a fixed length
                        if i + 1 < item_count:  # don't need to seek if this is the last item in the page
                            assert pos < page_base + page_size, "next item is located in current page"
                            wallet_file.seek(pos)
                    else: continue  # if not found on this page, continue to next page
                    break           # if we broke out of inner loop, break out of this one too

        if not mkey:
            if force_purepython:
                print(cls.program_name + ": warning: bsddb (Berkeley DB) module not found; try installing it to resolve key-not-found errors (see INSTALL.md)", file = sys.stderr)
            raise ValueError("Encrypted master key #1 not found in the Bitcoin Core wallet file.\n"+
                             "(is this wallet encrypted? is this a standard Bitcoin Core wallet?)")
        # This is a little fragile because it assumes the encrypted key and salt sizes are
        # 48 and 8 bytes long respectively, which although currently true may not always be
        # (it will loudly fail if this isn't the case; if smarter it could gracefully succeed):
        self = cls(loading=True)
        encrypted_master_key, self._salt, method, self._iter_count = struct.unpack_from(b"< 49p 9p I I", mkey)
        if method != 0: raise NotImplementedError("Unsupported Bitcoin Core key derivation method " + unicode(method))

        # only need the final 2 encrypted blocks (half of it padding) plus the salt and iter_count saved above
        self._part_encrypted_master_key = encrypted_master_key[-32:]
        return self

    # Import a Bitcoin Core encrypted master key that was extracted by extract-mkey.py
    @classmethod
    def load_from_data_extract(cls, mkey_data):
        # These are the same partial encrypted_master_key, salt, iter_count retrieved by load_from_filename()
        self = cls(loading=True)
        self._part_encrypted_master_key, self._salt, self._iter_count = struct.unpack(b"< 32s 8s I", mkey_data)
        return self

    def difficulty_info(self):
        return "{:,} SHA-512 iterations".format(self._iter_count)

    # Defer to either the cpu or OpenCL implementation
    def return_verified_password_or_false(self, passwords):
        return self._return_verified_password_or_false_opencl(passwords) if hasattr(self, "_cl_devices") \
          else self._return_verified_password_or_false_cpu(passwords)

    # This is the time-consuming function executed by worker thread(s). It returns a tuple: if a password
    # is correct return it, else return False for item 0; return a count of passwords checked for item 1
    def _return_verified_password_or_false_cpu(self, passwords):
        # Copy a global into local for a small speed boost
        l_sha512 = hashlib.sha512

        # Convert Unicode strings (lazily) to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = itertools.imap(lambda p: p.encode("utf_8", "ignore"), passwords)

        for count, password in enumerate(passwords, 1):
            derived_key = password + self._salt
            for i in xrange(self._iter_count):
                derived_key = l_sha512(derived_key).digest()
            part_master_key = CryptoUtil.aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
            #
            # If the last block (bytes 16-31) of part_encrypted_master_key is all padding, we've found it
            if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                return password if mode.tstr == str else password.decode("utf_8", "replace"), count

        return False, count

    # Load and initialize the OpenCL kernel for Bitcoin Core, given:
    #   devices - a list of one or more of the devices returned by get_opencl_devices()
    #   global_ws - a list of global work sizes, exactly one per device
    #   local_ws  - a list of local work sizes (or Nones), exactly one per device
    #   int_rate  - number of times to interrupt calculations to prevent hanging
    #               the GPU driver per call to return_verified_password_or_false()
    def init_opencl_kernel(self, devices, global_ws, local_ws, int_rate):
        # Need to save these for return_verified_password_or_false_opencl()
        assert devices, "WalletBitcoinCore.init_opencl_kernel: at least one device is selected"
        assert len(devices) == len(global_ws) == len(local_ws), "WalletBitcoinCore.init_opencl_kernel: one global_ws and one local_ws specified for each device"
        self._cl_devices   = devices
        self._cl_global_ws = global_ws
        self._cl_local_ws  = local_ws

        self._cl_kernel = self._cl_queues = self._cl_hashes_buffers = None  # clear any previously loaded
        cl_context = pyopencl.Context(devices)
        #
        # Load and compile the OpenCL program
        cl_program = pyopencl.Program(cl_context, open(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "../../sha512-bc-kernel.cl"))
            .read()).build(b"-w")
        #
        # Configure and store for later the OpenCL kernel (the entrance function)
        self._cl_kernel = cl_program.kernel_sha512_bc
        self._cl_kernel.set_scalar_arg_dtypes([None, numpy.uint32])
        #
        # Check the local_ws sizes
        for i, device in enumerate(devices):
            if local_ws[i] is None: continue
            max_local_ws = self._cl_kernel.get_work_group_info(pyopencl.kernel_work_group_info.WORK_GROUP_SIZE, device)
            if local_ws[i] > max_local_ws:
                error_exit("--local-ws of", local_ws[i], "exceeds max of", max_local_ws, "for GPU '"+device.name.strip()+"' with Bitcoin Core wallets")

        # Create one command queue and one I/O buffer per device
        self._cl_queues         = []
        self._cl_hashes_buffers = []
        for i, device in enumerate(devices):
            self._cl_queues.append(pyopencl.CommandQueue(cl_context, device))
            # Each buffer is of len --global-ws * (size-of-sha512-hash-in-bytes == 512 bits / 8 == 64)
            self._cl_hashes_buffers.append(pyopencl.Buffer(cl_context, pyopencl.mem_flags.READ_WRITE, global_ws[i] * 64))

        # Doing all iter_count iterations at once will hang the GPU, so instead calculate how
        # many iterations should be done at a time based on iter_count and the requested int_rate,
        # rounding up to maximize the number of iterations done in the last set to optimize performance
        assert hasattr(self, "_iter_count") and self._iter_count, "WalletBitcoinCore.init_opencl_kernel: bitcoin core wallet or mkey has been loaded"
        self._iter_count_chunksize = self._iter_count // int_rate or 1
        if self._iter_count_chunksize % int_rate != 0:  # if not evenly divisible,
            self._iter_count_chunksize += 1             # then round up

    def _return_verified_password_or_false_opencl(self, passwords):
        assert len(passwords) <= sum(self._cl_global_ws), "WalletBitcoinCore.return_verified_password_or_false_opencl: at most --global-ws passwords"

        # Convert Unicode strings to UTF-8 bytestrings
        if mode.tstr == unicode:
            passwords = map(lambda p: p.encode("utf_8", "ignore"), passwords)

        # The first iter_count iteration is done by the CPU
        hashes = numpy.empty([sum(self._cl_global_ws), 64], numpy.uint8)
        for i, password in enumerate(passwords):
            hashes[i] = numpy.frombuffer(hashlib.sha512(password + self._salt).digest(), numpy.uint8)

        # Divide up and copy the starting hashes into the OpenCL buffer(s) (one per device) in parallel
        done   = []  # a list of OpenCL event objects
        offset = 0
        for devnum, ws in enumerate(self._cl_global_ws):
            done.append(pyopencl.enqueue_copy(self._cl_queues[devnum], self._cl_hashes_buffers[devnum],
                                              hashes[offset : offset + ws], is_blocking=False))
            self._cl_queues[devnum].flush()  # Starts the copy operation
            offset += ws
        pyopencl.wait_for_events(done)

        # Doing all iter_count iterations at once will hang the GPU, so instead do iter_count_chunksize
        # iterations at a time, pausing briefly while waiting for them to complete, and then continuing.
        # Because iter_count is probably not evenly divisible by iter_count_chunksize, the loop below
        # performs all but the last of these iter_count_chunksize sets of iterations.

        i = 1 - self._iter_count_chunksize  # used if the loop below doesn't run (when --int-rate == 1)
        for i in xrange(1, self._iter_count - self._iter_count_chunksize, self._iter_count_chunksize):
            done = []  # a list of OpenCL event objects
            # Start up a kernel for each device to do one set of iter_count_chunksize iterations
            for devnum in xrange(len(self._cl_devices)):
                done.append(self._cl_kernel(self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                                            None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                                            self._cl_hashes_buffers[devnum], self._iter_count_chunksize))
                self._cl_queues[devnum].flush()  # Starts the kernel
            pyopencl.wait_for_events(done)

        # Perform the last remaining set of iterations (usually fewer then iter_count_chunksize)
        done = []  # a list of OpenCL event objects
        for devnum in xrange(len(self._cl_devices)):
            done.append(self._cl_kernel(self._cl_queues[devnum], (self._cl_global_ws[devnum],),
                                        None if self._cl_local_ws[devnum] is None else (self._cl_local_ws[devnum],),
                                        self._cl_hashes_buffers[devnum], self._iter_count - self._iter_count_chunksize - i))
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

        # Using the computed hashes, try to decrypt the master key (in CPU)
        for i, password in enumerate(passwords):
            derived_key = hashes[i].tostring()
            part_master_key = CryptoUtil.aes256_cbc_decrypt(derived_key[:32], self._part_encrypted_master_key[:16], self._part_encrypted_master_key[16:])
            # If the last block (bytes 16-31) of part_encrypted_master_key is all padding, we've found it
            if part_master_key == b"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10":
                return password if mode.tstr == str else password.decode("utf_8", "replace"), i + 1
        return False, i + 1
