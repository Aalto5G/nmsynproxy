package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "strconv"
    "net"
    "os"
    "github.com/pborman/getopt/v2"
)

func pack(mode string, ipaddr net.IP, port uint16, tcpmss uint16, tcpsack uint8, tcpwscale uint8) bytes.Buffer {
	buf := new(bytes.Buffer)
        binary.Write(buf, binary.BigEndian, ipaddr.To4())
        var port16 uint16 = port
        var proto8 uint8 = 6
        var flags8 uint8 = 0
        var tcpmss16 uint16 = tcpmss
        var tcpsack8 uint8 = tcpsack
        var tcpwscale8 uint8 = tcpwscale
        if mode == "flush" {
            flags8 |= (1<<4)
            tcpmss16 = 0
            tcpsack8 = 0
            tcpwscale8 = 0
            proto8 = 0
            port16 = 0
        } else if mode == "add" {
        } else if mode == "mod" {
            flags8 |= (1<<3)
        } else if mode == "del" {
            flags8 |= (1<<0)
            tcpmss16 = 0
            tcpsack8 = 0
            tcpwscale8 = 0
        }
        if port16 != 0 {
            flags8 |= (1<<1)
        }
        if proto8 != 0 {
            flags8 |= (1<<2)
        }
        binary.Write(buf, binary.BigEndian, port16)
        binary.Write(buf, binary.BigEndian, proto8)
        binary.Write(buf, binary.BigEndian, flags8)
        binary.Write(buf, binary.BigEndian, tcpmss16)
        binary.Write(buf, binary.BigEndian, tcpsack8)
        binary.Write(buf, binary.BigEndian, tcpwscale8)
        return *buf
}

func main() {
    helpFlag := getopt.Bool('h', "display help")
    ipaddrStr := getopt.StringLong("ipaddr", 'i', "127.0.0.1", "Dataplane IP address")
    portInt := getopt.IntLong("port", 'p', 12345, "Dataplane port")
    modeStr := getopt.EnumLong("mode", 'e', []string{"add","mod","del","flush"}, "add", "mode")
    dstAddrStr := getopt.StringLong("conn-dstaddr", 'd', "0.0.0.0", "Destination IP address")
    dstPortInt := getopt.IntLong("conn-dstport", 'o', 0, "Destination port")
    mssInt := getopt.IntLong("conn-tcpmss", 'm', 1460, "TCP MSS value")
    sackStr := getopt.EnumLong("conn-tcpsack", 's', []string{"0","1"}, "1", "TCP SACK [0, 1]")
    wscaleStr := getopt.EnumLong("conn-tcpwscale", 'w', []string{"0","1","2","3","4","5","6","7","8","9","10","11","12","13","14"}, "14", "TCP window scaling value [0-14]")
    getopt.Parse()
    args := getopt.Args()
    if *helpFlag {
        getopt.Usage()
        os.Exit(0)
    }
    ipaddr := net.ParseIP(*ipaddrStr)
    if ipaddr.To4() == nil {
        fmt.Fprintf(os.Stderr, "IPv4 address not valid <%s>\n", ipaddr)
        os.Exit(1)
    }
    if *portInt <= 0 || *portInt > 65535 {
        fmt.Fprintf(os.Stderr, "Port number not valid <%d>\n", *portInt)
        os.Exit(1)
    }
    dstAddr := net.ParseIP(*dstAddrStr)
    if dstAddr.To4() == nil {
        fmt.Fprintf(os.Stderr, "IPv4 address not valid <%s>\n", dstAddr)
        os.Exit(1)
    }
    if *dstPortInt < 0 || *dstPortInt > 65535 {
        fmt.Fprintf(os.Stderr, "Port number not valid <%d>\n", *dstPortInt)
        os.Exit(1)
    }
    if *mssInt <= 0 || *mssInt > 8960 {
        fmt.Fprintf(os.Stderr, "TCP MSS value not valid <%d> (1-8960)\n", *dstPortInt)
        os.Exit(1)
    }
    sack, err := strconv.Atoi(*sackStr)
    checkError(err)
    wscale, err := strconv.Atoi(*wscaleStr)
    checkError(err)
    if wscale < 0 || wscale > 14 {
        fmt.Fprintf(os.Stderr, "TCP window scale value not valid <%d> (0-14)\n", wscale)
        os.Exit(1)
    }
    if len(args) != 0 {
        getopt.Usage()
        os.Exit(1)
    }
    tcpAddr, err := net.ResolveTCPAddr("tcp4", ipaddr.String()+":"+strconv.Itoa(*portInt))
    checkError(err)
    conn, err := net.DialTCP("tcp", nil, tcpAddr)
    checkError(err)
    packed := pack(*modeStr, dstAddr, uint16(*dstPortInt), uint16(*mssInt), uint8(sack), uint8(wscale))
    _, err = conn.Write(packed.Bytes())
    checkError(err)
    bytes := make([]byte, 256)
    nbytes, err := conn.Read(bytes)
    checkError(err)
    if nbytes != 2 {
        fmt.Fprintf(os.Stderr, "Reply not of correct length\n")
        os.Exit(1)
    }
    fmt.Print(string(bytes))
    os.Exit(0)
}
func checkError(err error) {
    if err != nil {
        fmt.Fprintf(os.Stderr, "Fatal error: %s\n", err.Error())
        os.Exit(1)
    }
}
