package metrics

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/libp2p/go-libp2p-core/peer"
)

type ExtraMetrics struct {
	Peers sync.Map
}

// AddNewPeer adds a peer struct to the total list giving as a result a bool
// that will be true if the peer was already in the sync.Map (exists?)
func (em *ExtraMetrics) AddNewPeer(id peer.ID) bool {
	_, ok := em.Peers.Load(id)
	if ok { // the peer was already in the sync.Map return true
		return true
	}
	// Generate a new PeerExtraMetrics with the first attempt results
	pem := PeerExtraMetrics{
		ID:        id,
		Attempted: false,
		Succeed:   false,
		Attempts:  0,
		Error:     "None",
	}
	em.Peers.Store(id, pem)
	return false
}

// AddNewAttempts adds the resuts of a new attempt over an existing peer
// increasing the attempt counter and the respective fields
func (em *ExtraMetrics) AddNewAttempt(id peer.ID, succeed bool, err string) error {
	v, ok := em.Peers.Load(id)
	if !ok { // the peer was already in the sync.Map return true
		return fmt.Errorf("Not peer found with that ID %s", id.String())
	}
	// Update the counter and connection status
	pem := v.(PeerExtraMetrics)
	pem.NewAttempt(succeed, err)
	// Store the new struct in the sync.Map
	em.Peers.Store(id, pem)
	return nil
}

// CheckIdConnected check if the given peer was already connected
// returning true if it was connected before or false if wasn't
func (em *ExtraMetrics) CheckIdConnected(id peer.ID) bool {
	v, ok := em.Peers.Load(id)
	if !ok { // the peer was already in the sync.Map we didn't connect the peer -> false
		return false
	}
	// Check if the peer was connected
	pem := v.(PeerExtraMetrics)
	if pem.Succeed == true {
		return true
	} else {
		return false
	}
}

// Function that converts the content of the ExtraMetrics struct (content of the sync.Map)
// into a CSV
// TODO: to avoid code duplication, better to generate a new package called "exporter"
// 		 in charge of convert map[] or sync.Map into a csv/json
func (em ExtraMetrics) ExportCSV(filePath string) error {
	// Marshall the metrics into a json/csv
	tmpMap := make(map[string]PeerExtraMetrics)
	em.Peers.Range(func(k, v interface{}) bool {
		tmpMap[k.(peer.ID).String()] = v.(PeerExtraMetrics)
		return true
	})
	// Export the json to the given path/file
	// If we want to export it in json
	//embytes := json.Marshal(tmpMap)

	// to do it in csv
	csvFile, err := os.Create(filePath) // Create, New file, if exist overwrite
	if err != nil {
		return fmt.Errorf("Error Opening the file:", filePath)
	}
	defer csvFile.Close()
	// First raw of the file will be the Titles of the columns
	_, err = csvFile.WriteString("Peer Id,Attempted,Succeed,Attempts,Error\n")
	if err != nil {
		return fmt.Errorf("Error while Writing the Titles on the csv")
	}

	for k, v := range tmpMap {
		var csvRow string
		peerMetrics := v
		csvRow = k + "," + strconv.FormatBool(peerMetrics.Attempted) + "," +
			strconv.FormatBool(peerMetrics.Succeed) + "," + strconv.Itoa(peerMetrics.Attempts) + "," + peerMetrics.Error + "\n"
		_, err = csvFile.WriteString(csvRow)
		if err != nil {
			return fmt.Errorf("Error while Writing the Titles on the csv")
		}
	}
	return nil
}

type PeerExtraMetrics struct {
	ID        peer.ID // ID of the peer
	Attempted bool    // If the peer has been attempted to stablish a connection
	Succeed   bool    // If the connection attempt has been successful
	Attempts  int     // Number of attempts done
	Error     string  // Type of error that we detected
}

// Funtion that updates the values of the new connection trial increasing the counter
// as the result of the connection trial
func (p *PeerExtraMetrics) NewAttempt(success bool, err string) {
	if p.Attempted == false {
		p.Attempted = true
		//fmt.Println("Original ", err)
		if err != "" || err != "dial backoff" {
			p.Error = FilterError(err)
		}
	}
	if success == true {
		p.Succeed = success
		p.Error = "None"
	}
	p.Attempts += 1
}

// funtion that formats the error into a Pretty understandable (standard) way
// also important to cohesionate the extra-metrics output csv
func FilterError(err string) string {
	errorPretty := "Uncertain"
	// filter the error type
	if strings.Contains(err, "connection reset by peer") {
		errorPretty = "Connection reset by peer"
	} else if strings.Contains(err, "i/o timeout") {
		errorPretty = "i/o timeout"
	} else if strings.Contains(err, "dial to self attempted") {
		errorPretty = "dial to self attempted"
	} else if strings.Contains(err, "dial backoff") {
		errorPretty = "dial backoff"
	}

	return errorPretty
}
