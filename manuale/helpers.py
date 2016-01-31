def confirm(msg, default=True):
    while True:
        choices = 'Y/n' if default else 'y/N'
        answer = input("{} [{}] ".format(msg, choices)).strip().lower()

        if answer in { 'yes', 'y' } or (default and not answer):
            return True
        elif answer in { 'no', 'n' } or (not default and not answer):
            return False
