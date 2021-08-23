package metrics

import (
	//log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func Test_Peer(t *testing.T) {
	// TODO
	require.Equal(t, 1, 1)
}

func Test_GetConnectedTime(t *testing.T) {
	// simulate normal behaviour
	peer1 := Peer{}
	// connect 59 seconds
	peer1.AddConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	peer1.AddDisconnectionEvent(parseTime("2021-08-23T01:00:59.000Z", t))
	// connect 1 second
	peer1.AddConnectionEvent("inbound", parseTime("2021-08-25T01:00:00.000Z", t))
	peer1.AddDisconnectionEvent(parseTime("2021-08-25T01:00:01.000Z", t))
	conTime1 := peer1.GetConnectedTime()
	// total connection time 1 minute
	require.Equal(t, conTime1, float64(1))

	// simulate currently connected
	peer2 := Peer{}
	// 5 second connection
	peer2.AddConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	peer2.AddDisconnectionEvent(parseTime("2021-08-23T01:00:05.000Z", t))
	// 1 second connection
	peer2.AddConnectionEvent("inbound", parseTime("2021-09-25T01:00:00.000Z", t))
	peer2.AddDisconnectionEvent(parseTime("2021-09-25T01:00:01.000Z", t))
	// currently connected, no disc logged
	peer2.AddConnectionEvent("inbound", parseTime("2021-10-23T01:00:00.000Z", t))
	conTime2 := peer2.GetConnectedTime()
	// total connection 6 seconds (6/60)
	require.Equal(t, conTime2, float64(0.1))

	// simulate a faulty, no disconnection
	peer3 := Peer{}
	// connect 59 seconds
	peer3.AddConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	peer3.AddConnectionEvent("inbound", parseTime("2021-08-25T02:00:00.000Z", t))
	peer3.AddConnectionEvent("inbound", parseTime("2021-08-28T03:00:00.000Z", t))
	conTime3 := peer3.GetConnectedTime()
	require.Equal(t, conTime3, float64(0))

	// simulate a lost connection
	/* TODO: There is still an edge case not considered
	peer4 := Peer{}
	peer4.AddConnectionEvent("inbound", parseTime("2021-08-23T01:00:00.000Z", t))
	// this disconnection was lost
	peer4.AddConnectionEvent("inbound", parseTime("2021-08-25T01:00:00.000Z", t))
	peer4.AddDisconnectionEvent(parseTime("2021-08-25T01:00:06.000Z", t))
	conTime4 := peer4.GetConnectedTime()
	require.Equal(t, conTime4, float64(0.1))
	*/
}

func parseTime(strTime string, t *testing.T) time.Time {
	parsedTime, err := time.Parse(time.RFC3339, strTime)
	if err != nil {
		log.Error(err)
	}
	return parsedTime
}
