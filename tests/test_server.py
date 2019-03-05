import sys
sys.path.insert(0, '../')
import spa_lib

s = spa_lib.spaListener(db_passwd="password")

s.start()

try:
	s.block()
except KeyboardInterrupt as err:
	s.terminate()