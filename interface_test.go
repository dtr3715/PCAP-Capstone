package main

import (
    "fmt"
    "net"
)

func main() {
    ifaces, err := net.Interfaces()
    if err != nil {
        fmt.Print(fmt.Errorf(err.Error()))
        return
    }
    for _, iface := range ifaces {
		fmt.Print(iface.Name + "\n")
    }
}