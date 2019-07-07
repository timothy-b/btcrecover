# Estimate the # of bits of entropy per byte in a string using a simple histogram estimator
import math


class StringUtility:

    @staticmethod
    def est_entropy_bits(data):
        hist_bins = [0] * 256
        for byte in data:
            hist_bins[ord(byte)] += 1
        entropy_bits = 0.0
        for frequency in hist_bins:
            if frequency:
                prob = float(frequency) / len(data)
                entropy_bits += prob * math.log(prob, 2)
        return entropy_bits * -1
