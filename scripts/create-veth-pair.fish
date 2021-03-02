set -g VETH0 "veth0"
set -g VETH1 "veth1"
set -g IP1 "10.1.0.2/24"
set -g IP1_PING "10.1.0.2"
set -g IP0 "10.1.0.1/24"
set -g NETNS "test"

function create_pair -d "create veth pair with one side in different netns"
    ip link add $VETH0 type veth peer name $VETH1
    ip netns add $NETNS
    ip link set $VETH0 netns $NETNS
    ip link set $VETH1 up
    # ip link set $VETH0 up
    ip netns exec $NETNS ip link set $VETH0 up
    ip addr add $IP1 dev $VETH1
    ip netns exec $NETNS ip addr add $IP0 dev $VETH0
    # ip addr add 10.10.0.1/24 dev $VETH0
    # ip addr
    ip netns exec $NETNS ip addr
end

function cleanup_pair -d "cleanup veth pair and netns"
    ip link del $VETH1
    ip netns del $NETNS
end

function test_pair -d "test out the new pair by pinging between them"
    ip netns exec $NETNS ping -c 5 $IP1_PING
    # ping -c 5 10.10.0.2
end

cleanup_pair
create_pair
test_pair
