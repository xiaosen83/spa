import sys
sys.path.insert(0, '../')
import spa_lib

class Test():
	def __init__(self, aaa, bbb):
		self.aaa = aaa
		self.bbb = bbb
	def get_data(self):
		return self.bbb
	def add_data(self, num):
		self.bbb.append(num)

test = Test("aaa", [1,2,3])
test1 = test.copy()
print("test:{0}".format(test.get_data()))
print("test1:{0}".format(test1.get_data()))
test1.add_data(4)
print("test:{0}".format(test.get_data()))
print("test1:{0}".format(test1.get_data()))
exit()

s = spa_lib.iptableMonitor()

s.start()

try:
	s.block()
except KeyboardInterrupt as err:
	s.terminate()