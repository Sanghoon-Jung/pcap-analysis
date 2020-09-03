all: pcap-analysis

pcap-analysis: main.cpp classifier.cpp 
	g++ -o pcap-analysis main.cpp classifier.cpp stream.cpp -lpcap -lnet -g

clean:
	rm -rf pcap-analysis
