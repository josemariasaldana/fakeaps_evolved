/**
Fake Access Points (Evolved) using Atheros wireless cards in Linux

How to Compile:

- Get the `ieee80211.h` and `ieee80211_radiotap.h` headers from e.g. the MadWiFi distribution:

http://cvs.sourceforge.net/viewcvs.py/madwifi/madwifi/net80211/

$ gcc --std=gnu99 -Wall -o fakeaps_evolved fakeaps_evolved.c

Start the program

$ ./fakeaps_evolved [atheros raw device] [channel it is tuned to] [802.11 version: 'g' or 'n']


Before using it:
1. Customize the array of access points below, if you want.
2. Bring up your Atheros interface on the desired channel.
3. Enable the raw device (echo "1" > /proc/sys/dev/ath0/rawdev)
4. Configure the raw device to use radiotap headers (echo "2" > /proc/sys/dev/ath0/rawdev_type)
5. Bring up the raw device (ifconfig ath0raw up)


Improved by Jose Ruiz, Cristian Hernandez and Jose Saldana, from University of Zaragoza.

Initial version written by Evan Jones: http://www.evanjones.ca/software/fakeaps.c

Released under a BSD Licence
*/

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <fcntl.h>
//#include <netinet/ether.h>

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include <unistd.h>

#include <netinet/in.h>

#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include <sys/time.h>
#include <time.h>

// Comentar en máquinas minipcs
#include <linux/byteorder/big_endian.h>


#define __packed __attribute__((__packed__))
#include  "ieee80211.h"
#include  "ieee80211_radiotap.h"

//#define ARPHRD_IEEE80211 801
//#define ARPHRD_IEEE80211_PRISM 802


int openSocket( const char device[IFNAMSIZ] )
{
	struct ifreq ifr;
	struct sockaddr_ll ll;
	const int protocol = ETH_P_ALL;
	int sock = -1;
	
	assert( sizeof( ifr.ifr_name ) == IFNAMSIZ );

	sock = socket( PF_PACKET, SOCK_RAW, htons(protocol) );
	if ( sock < 0 )
	{
		perror( "socket failed (do you have root priviledges?)" );
		return -1;
	}
	
	memset( &ifr, 0, sizeof( ifr ) );
	strncpy( ifr.ifr_name, device, sizeof(ifr.ifr_name) );
	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0)
	{
		perror("ioctl[SIOCGIFINDEX]");
		close(sock);
		return -1;
	}

	memset( &ll, 0, sizeof(ll) );
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ll.sll_protocol = htons(protocol);
	ll.sll_halen = ETH_ALEN;

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Error\t: ioctl(SIOCGIFHWADDR) failed\n");
        return (-1);
    }

	memcpy(ll.sll_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	/*if (ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211 &&
            ifr.ifr_hwaddr.sa_family != ARPHRD_IEEE80211_PRISM) {
        fprintf( stderr, "Error\t: bad linktype\n. ifr_hwaddr.sa_family = %i ", ifr.ifr_hwaddr.sa_family);
        return (-1);
    }*/


	if ( bind( sock, (struct sockaddr *) &ll, sizeof(ll) ) < 0 ) {
		perror( "bind[AF_PACKET]" );
		close( sock );
		return -1;
	}
	// nonblocking I/O on the packet socket so we can poll
	fcntl(sock, F_SETFL, O_NONBLOCK);
		
	// Enable promiscuous mode
	struct packet_mreq mr;
	memset( &mr, 0, sizeof( mr ) );
	
	mr.mr_ifindex = ll.sll_ifindex;
	mr.mr_type    = PACKET_MR_PROMISC;

	if( setsockopt( sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof( mr ) ) < 0 )
	{
		perror( "setsockopt[PACKET_MR_PROMISC]" );
		close( sock );
		return -1;
	}
	
	return sock;
}

void packet_hexdump(const uint8_t* data, size_t size)
{
	size_t i;

	printf("%02x:", data[0]);
	for(i=1; i<size; i++){
		printf("%02x:", data[i]);
		if ( (i & 0xf)  == 0xf )
		{
			// Add a carrage return every 16 bytes
			printf( "\n" );
		}
	}
	printf("\n\n");
}

typedef struct {
  uint32_t msgcode;
  uint32_t msglen;
#define WLAN_DEVNAMELEN_MAX 16
  uint8_t devname[WLAN_DEVNAMELEN_MAX];
  uint32_t hosttime;
  uint32_t mactime;
  uint32_t channel;
  uint32_t rssi;
  uint32_t sq;
  uint32_t signal;
  uint32_t noise;
  uint32_t rate;
  uint32_t istx;
  uint32_t frmlen;
} wlan_ng_prism2_header;

/** Get the current 802.11 64-bit timestamp from the system time. */
uint64_t getCurrentTimestamp()
{
	struct timeval t;
	
	int code = gettimeofday( &t, NULL );
	assert( code == 0 );
	if ( code != 0 )
	{
		perror( "error calling gettimeofday" );
		assert( 0 );
	}
	
	// Convert seconds to microseconds
	// For the purposes of 802.11 timestamps, we don't care about what happens
	// when this value wraps. As long as the value wraps consistently, we are
	// happy
	uint64_t timestamp = t.tv_sec * 1000000LL;
	timestamp += t.tv_usec;
	
	return timestamp;
}

/** Add increment microseconds to time, computing the overflow correctly. */
void incrementTimeval( struct timeval* time, suseconds_t increment )
{
	assert( time != NULL );
	assert( 0 <= time->tv_usec && time->tv_usec < 1000000 );
	
	if ( increment >= 1000000 )
	{
		// Add the seconds to the seconds field, and keep the remainder
		time->tv_sec += (increment/1000000);
		increment = increment % 1000000;
	}
	
	assert( increment < 1000000 );
	
	time->tv_usec += increment;
	if ( time->tv_usec >= 1000000 )
	{
		time->tv_sec += 1;
		time->tv_usec -= 1000000;
		
		assert( 0 <= time->tv_usec && time->tv_usec < 1000000 );
	}
}

/** Computes "second = first - second" including the underflow "borrow." */ 
void differenceTimeval( const struct timeval* first, struct timeval* second )
{
	assert( first != NULL );
	assert( second != NULL );
	
	second->tv_sec = first->tv_sec - second->tv_sec;
	second->tv_usec = first->tv_usec - second->tv_usec;
	
	// If underflow occured, borrow a second from the higher field
	if ( second->tv_usec < 0 )
	{
		second->tv_sec -= 1;
		second->tv_usec += 1000000;
		
		// If this assertion fails, the initial timevals had invalid values
		assert( 0 <= second->tv_usec && second->tv_usec < 1000000 );
	}
}

/** Returns a negative integer if first < second, zero if first == second, and a positive integer if first > second. */
int compareTimeval( const struct timeval* first, const struct timeval* second )
{
	int difference = first->tv_sec - second->tv_sec;
	if ( difference == 0 )
	{
		// If the seconds fields are equal, compare based on the microseconds
		difference = first->tv_usec - second->tv_usec;
	}
	
	return difference;
}

struct AccessPointDescriptor
{
	uint8_t macAddress[IEEE80211_ADDR_LEN];
	const uint8_t* ssid;
	size_t ssidLength;
	const uint8_t* dataRates;
	size_t dataRatesLength;
};

static const uint8_t IEEE80211_BROADCAST_ADDR[IEEE80211_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static const uint8_t IEEE80211B_DEFAULT_RATES[] = { 
	IEEE80211_RATE_BASIC | 2,
	IEEE80211_RATE_BASIC | 4,
	11,
	22,
};
//~ static const size_t IEEE80211B_DEFAULT_RATES_LENGTH = sizeof(IEEE80211B_DEFAULT_RATES);
#define IEEE80211B_DEFAULT_RATES_LENGTH sizeof(IEEE80211B_DEFAULT_RATES)

struct ieee80211_beacon {
	u_int64_t beacon_timestamp;
	u_int16_t beacon_interval;
	u_int16_t beacon_capabilities;
} __attribute__((__packed__));

struct ieee80211_info_element {
	u_int8_t info_elemid;
	u_int8_t info_length;
	u_int8_t* info[0];
} __attribute__((__packed__));

/** Converts a 16-bit integer from host byte order to little-endian byte order. Not implement yet. */
// inline uint16_t htole16( uint16_t src ) { return src; };

/*uint8_t* paquete_wifi_probe = "\x00\x00\x0e\x00\x04\x84\x02\x00\x6c\x00\x00\x00\x0b\x00\x50\x00\x00\x00\xda\xa1\x19\x1d\x41\xc4\x00\x1b\xb3\x1d\x41\xc4\x00\x1b\xb3\x1d\x41\xc4\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00\x01\x00\x00\x08\x77\x69\x35\x2d\x64\x65\x6d\x6f\x01\x08\x0c\x12\x18\x24\x30\x48\x60\x6c\x03\x01\x01\x05\x04\x00\x01\x00\x00";
size_t    lon_paquete_wifi_probe = 79;
uint8_t* paquete_wifi_beacon = "\x00\x00\x09\x00\x00\x00\x00\x04\x04\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\xf4\xf2\x6d\x0c\x9d\xaa\xf4\xf2\x6d\x0c\x9d\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x64\x00\x01\x00\x03\x61\x70\x30\x01\x04\x82\x84\x0b\x16\x03\x01\x01";
size_t    lon_paquete_wifi_beacon = 59;*/



#define BEACON_INTERVAL 102400

/** Returns a beacon packet for the specified descriptor. The packet will be allocated using malloc. */
uint8_t* constructBeaconPacket( uint8_t dataRate, uint8_t channel, const struct AccessPointDescriptor* apDescription, size_t* beaconLength, char version )
{
	struct {
		uint8_t known;		/* The known field indicates which
					 * information is known               */
		uint8_t flags;
		uint8_t mcs;			/* The mcs field indicates the MCS rate
					 * index as in IEEE_802.11n-2009      */
	} mcs;
	
	// Validate parameters
	assert( apDescription != NULL );
	assert( beaconLength != NULL );
	
	assert( 0 <= apDescription->ssidLength && apDescription->ssidLength <= 32 );
	assert( 1 <= apDescription->dataRatesLength && apDescription->dataRatesLength <= 8 );
	
	uint8_t dataRateValue = (dataRate & IEEE80211_RATE_VAL);
	// For 802.11b, either 1 or 2 Mbps is the permitted rate for broadcasts
	// For 802.11a, 6Mbps is the permitted rate for broadcasts
	assert( dataRateValue == 0x02 || dataRateValue == 0x04 || dataRateValue == 0x12 ); 
	
	// Packet size: radiotap header + 1 byte for rate + ieee80211_frame header + beacon info + tags
	if (version == 'g')
		*beaconLength = sizeof(struct ieee80211_radiotap_header) + sizeof(dataRate) +
			sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_beacon) +
			//SSID, rates, channel
			sizeof(struct ieee80211_info_element)*3 + apDescription->ssidLength +
			apDescription->dataRatesLength + sizeof(channel);

	else if (version == 'n')
		*beaconLength = sizeof(struct ieee80211_radiotap_header) + sizeof (mcs) +
			sizeof(struct ieee80211_frame) + sizeof(struct ieee80211_beacon) +
			//SSID, rates, channel
			sizeof(struct ieee80211_info_element)*3 + apDescription->ssidLength +
			apDescription->dataRatesLength + sizeof(channel);

	else
		return NULL;

	uint8_t* packet = (uint8_t*) malloc( *beaconLength );
	assert( packet != NULL );
	if ( packet == NULL )
	{
		return NULL;
	}
	
	size_t remainingBytes = *beaconLength;
	
	// Add the radiotap header
	assert( remainingBytes >= sizeof(struct ieee80211_radiotap_header) );
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packet;
	uint8_t* packetIterator = packet + sizeof(*radiotap);
	remainingBytes -= sizeof(*radiotap);
	
	radiotap->it_version = 0;

	if (version == 'g') {
		//radiotap->it_len = __cpu_to_le16(sizeof(*radiotap) + sizeof(dataRate));
		radiotap->it_len = sizeof(*radiotap) + sizeof(dataRate);
		radiotap->it_present = (1 << IEEE80211_RADIOTAP_RATE);

		// Add the data rate for the radiotap header
		assert( remainingBytes >= sizeof(dataRate) );
		*packetIterator = (dataRate & IEEE80211_RATE_VAL);
		packetIterator ++;
		remainingBytes -= sizeof(dataRate);
	}

	else if (version == 'n') {
		//radiotap->it_len = __cpu_to_le16(sizeof(*radiotap) + sizeof(mcs)); //FIXME comment in minipcs
		radiotap->it_len = sizeof(*radiotap) + sizeof(mcs);

		//radiotap->it_present = __cpu_to_le32((1 << IEEE80211_RADIOTAP_MCS)); //FIXMEcomment in minipcs
		radiotap->it_present = (1 << IEEE80211_RADIOTAP_MCS);

		assert( remainingBytes >= sizeof(mcs) );
		mcs.mcs = 0;
		mcs.flags = IEEE80211_RADIOTAP_MCS_BW_20
							| IEEE80211_RADIOTAP_MCS_SGI;
		mcs.known = IEEE80211_RADIOTAP_MCS_HAVE_MCS
							| IEEE80211_RADIOTAP_MCS_HAVE_BW
							| IEEE80211_RADIOTAP_MCS_HAVE_GI;
		*packetIterator = mcs.known;
		packetIterator ++;
		*packetIterator = mcs.flags;
		packetIterator ++;
		*packetIterator = mcs.mcs;
		packetIterator ++;
		remainingBytes -= sizeof(mcs);
	}

	else { // version different from 'g' or 'n'
		return NULL;
	}

	// Build the 802.11 header
	assert( remainingBytes >= sizeof(struct ieee80211_frame) );
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) packetIterator;
	packetIterator += sizeof(*dot80211);
	remainingBytes -= sizeof(*dot80211);
	
	// Beacon packet flags
	dot80211->i_fc[0] = IEEE80211_FC0_VERSION_0 | IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	dot80211->i_fc[1] = IEEE80211_FC1_DIR_NODS;
	dot80211->i_dur[0] = 0x0;
	dot80211->i_dur[1] = 0x0;
	// Destination = broadcast (no retries)
	memcpy( dot80211->i_addr1, IEEE80211_BROADCAST_ADDR, IEEE80211_ADDR_LEN );
	// Source = our own mac address
	memcpy( dot80211->i_addr2, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// BSS = our mac address
	memcpy( dot80211->i_addr3, apDescription->macAddress, IEEE80211_ADDR_LEN );
	// Sequence control: Automatically set by the driver
	
	// Add the beacon frame
	assert( remainingBytes >= sizeof(struct ieee80211_beacon) );
	struct ieee80211_beacon* beacon = (struct ieee80211_beacon*) packetIterator;
	packetIterator += sizeof(*beacon);
	remainingBytes -= sizeof(*beacon);
	
	beacon->beacon_timestamp = 0;
	// interval = 100 "time units" = 102.4 ms
	// Each time unit is equal to 1024 us
	//beacon->beacon_interval = htole16( BEACON_INTERVAL/1024 );
	beacon->beacon_interval = BEACON_INTERVAL/1024;
	// capabilities = sent by ESS
	beacon->beacon_capabilities = 0x0001;
	//beacon->beacon_capabilities = htole16( 0x0001 );
	
	// Add the SSID
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->ssidLength );
	struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->ssidLength;
	
	info->info_elemid = IEEE80211_ELEMID_SSID;
	info->info_length = apDescription->ssidLength;
	memcpy( info->info, apDescription->ssid, apDescription->ssidLength );
	
	// Add the data rates
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	remainingBytes -= sizeof(struct ieee80211_info_element) + apDescription->dataRatesLength;
	
	info->info_elemid = IEEE80211_ELEMID_RATES;
	info->info_length = apDescription->dataRatesLength;
	memcpy( info->info, apDescription->dataRates, apDescription->dataRatesLength );
	
	// Add the channel
	assert( remainingBytes >= sizeof(struct ieee80211_info_element) + sizeof(channel) );
	info = (struct ieee80211_info_element*) packetIterator;
	packetIterator += sizeof(struct ieee80211_info_element) + sizeof(channel);
	remainingBytes -= sizeof(struct ieee80211_info_element) + sizeof(channel);
	
	info->info_elemid = IEEE80211_ELEMID_DSPARMS;
	info->info_length = sizeof(channel);
	memcpy( info->info, &channel, sizeof(channel) );
	
	assert( remainingBytes == 0 );
	return packet;
}


// FIXME: add an 802.11n version of the probe response
void transmitProbeResponse( int rawSocket, uint8_t* beaconPacket, size_t beaconLength, const uint8_t* destinationMAC/*, char version*/ )
{
	// Probe responses are identical to beacon packets, except that
	// they are directed and not broadcast, and they are
	// set to be the probe response type
	
	// Find the 802.11 frame
	struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) beaconPacket;
	struct ieee80211_frame* dot80211 = (struct ieee80211_frame*) (beaconPacket + radiotap->it_len);
	
	dot80211->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_PROBE_RESP;
	memcpy( dot80211->i_addr1, destinationMAC, IEEE80211_ADDR_LEN );
		
	// Send the packet
	ssize_t bytes = write( rawSocket, beaconPacket, beaconLength );
	assert( bytes == (ssize_t) beaconLength );
	
	// Set the values back to what they should be for broadcast packets
	dot80211->i_fc[0] = IEEE80211_FC0_TYPE_MGT | IEEE80211_FC0_SUBTYPE_BEACON;
	memcpy( dot80211->i_addr1, IEEE80211_BROADCAST_ADDR, IEEE80211_ADDR_LEN );
}



// ADD MORE ACCESS POINTS HERE, IF YOU WANT
static struct AccessPointDescriptor ap0 = {
//	{ 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc },
	{ 0xF4, 0xF2, 0x6d, 0x0c, 0x9d, 0xaa },
	(const uint8_t*) "ap0", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};



/*static struct AccessPointDescriptor ap1 = {
//	{ 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54 },
	{ 0xdc, 0xef, 0x09, 0xe6, 0x9c, 0xdb },
	(const uint8_t*) "ap1", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

// Clients will only rarely detect this access point
// I think it takes too long to get to this probe response
static struct AccessPointDescriptor ap2 = {
	{ 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff },
	(const uint8_t*) "ap2", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

static struct AccessPointDescriptor ap3 = {
	{ 0xca, 0xfe, 0x00, 0xba, 0xbe, 0x00 },
	(const uint8_t*) "ap3", 3,
	IEEE80211B_DEFAULT_RATES, IEEE80211B_DEFAULT_RATES_LENGTH,
};

static const struct AccessPointDescriptor* accessPoints[] = {
	&ap0, &ap1, &ap2, &ap3,
};
*/

static const struct AccessPointDescriptor* accessPoints[] = {
	&ap0,
};

static const size_t numAccessPoints = sizeof(accessPoints) / sizeof(*accessPoints);

/** These offsets start from the beginning of the 802.11 frame. */
static const size_t PROBE_SSID_OFFSET = sizeof( struct ieee80211_frame );
static const size_t BEACON_TIMESTAMP_OFFSET = sizeof( struct ieee80211_frame );

void help()
{
	printf( "$ ./fakeaps_evolved [atheros raw device] [channel it is tuned to] [802.11 version: 'g' or 'n']\n" );
}


int main(int argc, char *argv[])
{
	size_t i;
	if ( argc != 4 )
	{
		help();
		return 1;
	}
	
	long int channel = strtol( argv[2], NULL, 10 );
	if ( channel <= 0 || 255 <= channel )
	{
		printf( "The channel must be between 1 and 255.\n" );
		help();
		return 1;
	}
	
	// version of 802.11 used
	char version = argv[3][0];

	printf("%c\n", version );

	if (strlen(argv[3]) != 1) {
		printf( "The version must be 'g' or 'n'.\n" );
		help();
		return 1;	
	}

	if ( (version != 'g') && (version != 'n') ) {
		printf( "The version must be 'g' or 'n'.\n" );
		help();
		return 1;
	}

	// The 802.11b base broadcast rate
	const uint8_t dataRate = 0x4;
	const char* device = argv[1];

		
	// Construct the beacon packets
	size_t* beaconLengths = (size_t*) malloc( sizeof(size_t) * numAccessPoints );
	assert( beaconLengths != NULL );
	uint8_t** beaconPackets = (uint8_t**) malloc( sizeof(uint8_t*) * numAccessPoints );
	assert( beaconLengths != NULL );

	assert( (version == 'g') || (version == 'n') );
	for ( i = 0; i < numAccessPoints; ++ i )
	{
		beaconPackets[i] = constructBeaconPacket( dataRate, channel, accessPoints[i], &beaconLengths[i], version );			
		assert( beaconPackets[i] != NULL );
		assert( beaconLengths[i] > 0 );
	}

	// Open the raw device
	int rawSocket = openSocket( device );
	if ( rawSocket < 0 )
	{
		fprintf( stderr, "error opening socket\n" );
		return 1;
	}
	
	// Configure the initial timeout
	struct timeval now;
	int code = gettimeofday( &now, NULL );
	assert( code == 0 );
	
	struct timeval beaconTime = now;
	incrementTimeval( &beaconTime, BEACON_INTERVAL );
	
	// This is used to change the sequence of the probe response messages
	// In order to help clients find more of our fake access points
	//size_t lastProbeStartIndex = 0;
	
	while ( 1 )
	{
		// We need to wait until one of two conditions:
		// 1. The "sockin" socket has data for us
		// 2. The beacon interval (102400 microseconds) has expired
		fd_set readfds;
		FD_ZERO( &readfds );
		FD_SET( rawSocket, &readfds );
		
		struct timeval timeout = now;
		differenceTimeval( &beaconTime, &timeout );
		int numFds = select( rawSocket+1, &readfds, NULL, NULL, &timeout );
		assert( numFds >= 0 );
		if ( numFds < 0 )
		{
			perror( "select failed" );
			return 1;
		}
		
		if ( numFds == 1 )
		{
			// We have a packet waiting: Read it
			uint8_t packetBuffer[4096];
			ssize_t bytes = read( rawSocket, packetBuffer, sizeof(packetBuffer) );
			if ( bytes < 0 )
			{
				perror( "read failed" );
				return 1;
			}
			
			//packet_hexdump( (const uint8_t*) packetBuffer, bytes );
			// Move past the radiotap header
			/*assert( bytes >= (ssize_t) sizeof( struct ieee80211_radiotap_header ) );
			struct ieee80211_radiotap_header* radiotap = (struct ieee80211_radiotap_header*) packetBuffer;
			assert( radiotap->it_version == 0 );
			assert( bytes >= radiotap->it_len );
			uint8_t* packetIterator = packetBuffer + radiotap->it_len;
			size_t remainingBytes = bytes - radiotap->it_len;*/
			
			// Get the 802.11 frame:
			// NOTE: This frame structure is larger than some packet types, so only read the initial bytes
			//struct ieee80211_frame* frame = (struct ieee80211_frame*)( packetIterator );
			
			// Check to see if this is a PROBE_REQUEST
			//assert( (frame->i_fc[0] & IEEE80211_FC0_VERSION_MASK) == IEEE80211_FC0_VERSION_0 );
			
			/*if ( (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK) == IEEE80211_FC0_TYPE_MGT &&
				(frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK) == IEEE80211_FC0_SUBTYPE_PROBE_REQ )
			{
				//~ packet_hexdump( (const uint8_t*) frame, remainingBytes );
				
				// Locate the SSID
				assert( remainingBytes >= PROBE_SSID_OFFSET );
				packetIterator += PROBE_SSID_OFFSET;
				remainingBytes -= PROBE_SSID_OFFSET;
				struct ieee80211_info_element* info = (struct ieee80211_info_element*) packetIterator;
				assert( remainingBytes >= sizeof(*info) );
				packetIterator += sizeof(*info);
				remainingBytes -= sizeof(*info);
				assert( remainingBytes >= info->info_length );
				
				// See if it is a broadcast ssid (zero length SSID)
				if ( info->info_length == 0 )
				{
					//~ printf( "broadcast probe request!\n");
					
					// Start with the next index for the next broadcast probe
					size_t index = lastProbeStartIndex;
					lastProbeStartIndex += 1;
					if ( lastProbeStartIndex >= numAccessPoints )
					{
						lastProbeStartIndex = 0;
					}
					
					// Transmit responses for all access points
					for ( size_t i = 0; i < numAccessPoints; ++ i )
					{
						if ( index >= numAccessPoints )
						{
							index = 0;
						}
						transmitProbeResponse( rawSocket, beaconPackets[index], beaconLengths[index], frame->i_addr2 );
						index += 1;
					}
				}
				else
				{
					// Check if the SSID matches any of ours
					for ( size_t i = 0; i < numAccessPoints; ++ i )
					{
						if ( info->info_length == accessPoints[i]->ssidLength && memcmp( info->info, accessPoints[i]->ssid, info->info_length ) == 0 )
						{
							// It does!
							//~ printf( "probe for SSID '%.*s'\n", info->info_length, (char*) info->info );
							transmitProbeResponse( rawSocket, beaconPackets[i], beaconLengths[i], frame->i_addr2 );
							break;
						}
					}
				}
			}*/
		}
		else
		{
			// We should only have 1 or 0 fds ready
			assert( numFds == 0 );
		}
		
		// Get the current time to calculate how much longer we need to wait
		// or if we need to send a beacon now
		int code = gettimeofday( &now, NULL );
		assert( code == 0 );
		
		if ( compareTimeval( &beaconTime, &now ) <= 0 )
		{
			//~ printf( "beacon\n" );
			// The timeout has expired. Send out the beacons
			// TODO: Update the timestamp in the beacon packets
			for ( i = 0; i < numAccessPoints; ++ i )
			{
				ssize_t bytes = write( rawSocket, beaconPackets[i], beaconLengths[i] );
				assert( bytes == (ssize_t) beaconLengths[i] );
				packet_hexdump( (const uint8_t*) beaconPackets[i], beaconLengths[i] );
				/*ssize_t bytes = write( rawSocket, paquete_wifi_probe, lon_paquete_wifi_probe );
				assert( bytes == (ssize_t) lon_paquete_wifi_probe);
				packet_hexdump( paquete_wifi_probe, lon_paquete_wifi_probe );
				bytes = write( rawSocket, paquete_wifi_beacon, lon_paquete_wifi_beacon );
				assert( bytes == (ssize_t) lon_paquete_wifi_beacon);
				packet_hexdump( paquete_wifi_beacon, lon_paquete_wifi_beacon );*/
				if ( bytes < (ssize_t) beaconLengths[i] )
				{
					perror( "error sending packet" );
					return 1;
				}
			}
			
			// Increment the next beacon time until it is in the future
			do {
				incrementTimeval( &beaconTime, BEACON_INTERVAL );
			} while( compareTimeval( &beaconTime, &now ) <= 0 );
		}
	}
	
	close( rawSocket );
	free( beaconPackets );
	free( beaconLengths );
}
