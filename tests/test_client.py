import sys
sys.path.insert(0, '../')
import spa_lib

aid = "1e9b8da6ca2a47de863e74dbbe8d926f"
seed = "46facea41fdd11e8acf9646e69b26c4f"
new_seed = "46facea41fdd11e8acf9646e69b26c4a"
password="jaskdaj"

knock_port=22
spa_server='10.103.220.134'

spa_lib.send_spa(aid, password, seed, new_seed, spa_lib.get_network_ip(), knock_port, server_ip=spa_server)
