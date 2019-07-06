############### NULL ###############
# A fake wallet which has no correct password;
# used for testing password generation performance


class WalletNull(object):

    @staticmethod
    def passwords_per_seconds(seconds):
        return max(int(round(500000 * seconds)), 1)

    @staticmethod
    def return_verified_password_or_false(passwords):
        return False, len(passwords)
