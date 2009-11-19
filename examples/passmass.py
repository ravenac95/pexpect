#!/usr/bin/env python

"""Change passwords on the named machines. passmass host1 host2 host3 . . .
Note that login shell prompt on remote machine must end in >, # or $. """

import pexpect
import sys, getpass

USAGE = '''passmass host1 host2 host3 . . .'''
COMMAND_PROMPT = '[>\$#] '
TERMINAL_PROMPT = r'Terminal type\?'
TERMINAL_TYPE = 'vt100'
SSH_NEWKEY = r'Are you sure you want to continue connecting \(yes/no\)\?'

def login(host, user, password):

    child = pexpect.spawn('ssh -l %s %s'%(user, host))
    fout = open ("LOG.TXT","wb")
    child.logfile = fout

    i = child.expect([pexpect.TIMEOUT, SSH_NEWKEY, '[Pp]assword: '])
    if i == 0: # Timeout
        print('ERROR!')
        print('SSH could not login. Here is what SSH said:')
        print(child.before, child.after)
        sys.exit (1)
    if i == 1: # SSH does not have the public key. Just accept it.
        child.sendline ('yes')
        child.expect ('[Pp]assword: ')
    child.sendline(password)
    # Now we are either at the command prompt or
    # the login process is asking for our terminal type.
    i = child.expect (['Permission denied', TERMINAL_PROMPT, COMMAND_PROMPT])
    if i == 0:
        print('Permission denied on host:', host)
        sys.exit (1)
    if i == 1:
        child.sendline (TERMINAL_TYPE)
        child.expect (COMMAND_PROMPT)
    return child

# (current) UNIX password:
def change_password(child, user, oldpassword, newpassword):

    child.sendline('passwd') 
    i = child.expect(['(?i)old password:', '(?i)current.*password:', '(?i)new.*password:'])
    # Root does not require old password, so it gets to bypass the next step.
    if i == 0 or i == 1:
        child.sendline(oldpassword)
        child.expect('(?i)new.*password:')
    child.sendline(newpassword)
    child.expect('(?i)new.*password:')
    child.sendline(newpassword)
    i = child.expect(['(?i)new.*password:', 'do not match', 'successfully'])
    if i == 0:
        print('Host did not like new password. Here is what it said...')
        print(child.before+child.match.string)
        # On Linux, sending Ctrl-C can't quit passwd. 
        while(1):
            child.sendline()
            # passwd: Authentication token manipulation error
            r = child.expect(['(?i)new.*password:', 'error'])
            if(r == 1):
                break
        return -1
    if(i==1):
        print('Sorry, passwords do not match.')
        return -2
    print('Password updated successfully.')
    return 0


def main():

    if len(sys.argv) <= 1:
        print(USAGE)
        return 1

    user = input('Username: ')
    password = getpass.getpass('Current Password: ')
    newpassword = getpass.getpass('New Password: ')
    newpasswordconfirm = getpass.getpass('Confirm New Password: ')
    if newpassword != newpasswordconfirm:
        print('New Passwords do not match.')
        return 1

    for host in sys.argv[1:]:
        child = login(host, user, password)
        if child == None:
            print('Could not login to host:', host)
            continue
        print('Changing password on host:', host)
        change_password(child, user, password, newpassword)
        child.expect(COMMAND_PROMPT)
        child.sendline('exit')

if __name__ == '__main__':
    try:
        main()
    except pexpect.ExceptionPexpect as e:
        import traceback
        traceback.print_exc()

