package main

import (
    "fmt"
    "net"
	"log"
	"strings"
)

func getInterface() string {
    ifaces, err := net.Interfaces()
    if err != nil {
        log.Fatal(err)
		return ""
    }
	for _, iface := range ifaces {
		if (iface.Name != "lo" && !strings.Contains(iface.Name, "Loopback")) {
			return iface.Name
		}
	}
	return ""
}

func main() {
	fmt.Println(getInterface())
}