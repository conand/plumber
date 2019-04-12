
from subprocess import Popen, PIPE
def main():
    p = Popen(['/home/degrigis/Projects/CHESS-hackathon/angr-dev/plumber/tests/example_1_nonet/example_1_nonet.bin', 'secret_of_life', 'password'], stdout=PIPE, stdin=PIPE)
    out = p.communicate(input=b'password')[0]
    print('PRIVDATA=' + out.decode('utf-8').split("\n")[-1])
if __name__ == '__main__':
    main()
            
