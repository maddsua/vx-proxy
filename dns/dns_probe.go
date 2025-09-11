package dns

import (
	"fmt"
	"net"
	"time"
)

func ProbeDnsServer(addr string) error {

	const probeTimeout = 5 * time.Second

	conn, err := net.DialTimeout("udp", addr, probeTimeout)
	if err != nil {
		return err
	}

	defer conn.Close()

	conn.SetDeadline(time.Now().Add(probeTimeout))

	//	don't look at this for too long.
	//	all that we're doing here is testing if a server responds with something.
	//	VX isn't a comprehensive service scanner. If you put in an address that ain't a DNS but answers on appropriate ports - that's on you.

	var dnsQuery = []byte{
		//	some bullshit I copied from the glorified google search
		0x00, 0x01, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,

		//	asking for directions to 'one.one.one.one' here
		0x03, 'o', 'n', 'e',
		0x03, 'o', 'n', 'e',
		0x03, 'o', 'n', 'e',
		0x03, 'o', 'n', 'e',

		//	finalize the query with some more binary garbage
		0x00, 0x00, 0x01, 0x00, 0x01,
	}

	if _, err := conn.Write(dnsQuery); err != nil {
		return fmt.Errorf("query: %v", err)
	}

	response := make([]byte, 512)
	if _, err := conn.Read(response); err != nil {
		return fmt.Errorf("no response")
	}

	return nil
}
