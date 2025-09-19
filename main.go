package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
	"github.com/armon/go-socks5"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	UserSSH    string `json:"userssh"`
	SSHPassEnc string `json:"ssh_password_encrypted"`
	IP         string `json:"ip"`
	SSHPort    string `json:"sshport"`
	SocksPort  string `json:"socksport"`
}

var encryptionKey = []byte("12345678901234567890123456789012") // 32 bytes for AES-256

var (
	sshClient     *ssh.Client
	socksServer   *socks5.Server
	logText       *widget.Label
	stopChan      chan struct{}
	wg            sync.WaitGroup
	connectBtn    *widget.Button
	disconnectBtn *widget.Button
	running       bool // اضافه شده برای جلوگیری از اجرای همزمان
	mu            sync.Mutex
)

func main() {
	// Initialize Fyne app
	myApp := app.New()
	myWindow := myApp.NewWindow("MK SSH Tunnel")

	// Create log display
	logText = widget.NewLabel("")
	logScroll := container.NewVScroll(logText)
	logScroll.SetMinSize(fyne.NewSize(400, 200))

	// Create input fields
	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("SSH Username")
	passEntry := widget.NewPasswordEntry()
	passEntry.SetPlaceHolder("SSH Password")
	ipEntry := widget.NewEntry()
	ipEntry.SetPlaceHolder("SSH Server IP")
	sshPortEntry := widget.NewEntry()
	sshPortEntry.SetPlaceHolder("SSH Port")
	socksPortEntry := widget.NewEntry()
	socksPortEntry.SetPlaceHolder("SOCKS5 Port")

	// Load config if exists
	config, err := loadConfig()
	if err == nil {
		userEntry.SetText(config.UserSSH)
		if decryptedPass, err := decryptPassword(config.SSHPassEnc); err == nil {
			passEntry.SetText(decryptedPass)
		} else {
			updateLog(fmt.Sprintf("⚠️ Failed to decrypt password from config: %v", err))
		}
		ipEntry.SetText(config.IP)
		sshPortEntry.SetText(config.SSHPort)
		socksPortEntry.SetText(config.SocksPort)
		updateLog("✅ Loaded config from config.json")
	}

	// Create buttons
	connectBtn = widget.NewButton("Connect", func() {
		mu.Lock()
		if running {
			updateLog("⚠️ Tunnel is already running")
			mu.Unlock()
			return
		}
		running = true
		mu.Unlock()
		go startTunnel(userEntry.Text, passEntry.Text, ipEntry.Text, sshPortEntry.Text, socksPortEntry.Text)
	})
	disconnectBtn = widget.NewButton("Disconnect", func() {
		stopTunnel()
	})
	disconnectBtn.Disable()

	// Layout
	inputGrid := container.NewGridWithColumns(2,
		widget.NewLabel("Username:"), userEntry,
		widget.NewLabel("Password:"), passEntry,
		widget.NewLabel("IP:"), ipEntry,
		widget.NewLabel("SSH Port:"), sshPortEntry,
		widget.NewLabel("SOCKS5 Port:"), socksPortEntry,
	)
	buttons := container.NewHBox(connectBtn, disconnectBtn)
	content := container.NewVBox(
		widget.NewLabelWithStyle("MK SSH Tunnel", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
		inputGrid,
		buttons,
		widget.NewLabel("Logs:"),
		logScroll,
	)

	// Set window content and show
	myWindow.SetContent(container.NewPadded(content))
	myWindow.Resize(fyne.NewSize(500, 400))
	myWindow.ShowAndRun()
}

func startTunnel(user, pass, ip, sshPort, socksPort string) {
	defer func() {
		mu.Lock()
		running = false
		mu.Unlock()
	}()

	updateLog("Starting SSH tunnel...")

	// Save config
	config := Config{
		UserSSH:   user,
		IP:        ip,
		SSHPort:   sshPort,
		SocksPort: socksPort,
	}
	encryptedPass, err := encryptPassword(pass)
	if err != nil {
		updateLog(fmt.Sprintf("❌ Failed to encrypt password: %v", err))
		return
	}
	config.SSHPassEnc = encryptedPass
	saveConfig(config)

	// SSH configuration
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(pass),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Connect to SSH server with retry
	sshAddr := fmt.Sprintf("%s:%s", ip, sshPort)
	for i := 0; i < 3; i++ {
		updateLog(fmt.Sprintf("🔍 Attempt %d to connect to SSH server (%s)...", i+1, sshAddr))
		sshClient, err = ssh.Dial("tcp", sshAddr, sshConfig)
		if err == nil {
			break
		}
		updateLog(fmt.Sprintf("⚠️ Attempt %d failed: %v", i+1, err))
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		updateLog(fmt.Sprintf("❌ Failed to connect to SSH server after 3 attempts: %v", err))
		return
	}
	defer sshClient.Close() // اطمینان از بسته شدن SSH

	// Initial SSH tunnel test
	updateLog("🔍 Testing initial SSH tunnel connection...")
	testConn, err := sshClient.Dial("tcp", "8.8.8.8:53")
	if err != nil {
		updateLog(fmt.Sprintf("⚠️ Initial connection test failed: %v", err))
	} else {
		updateLog("✅ Initial connection test succeeded")
		testConn.Close()
	}

	// Custom resolver that disables DNS resolving
	noOpResolver := &NoOpResolver{}

	// SOCKS5 server configuration
	socks5Conf := &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var conn net.Conn
			for i := 0; i < 3; i++ {
				updateLog(fmt.Sprintf("🔄 Attempt %d to forward raw domain %s via SSH tunnel", i+1, addr))
				conn, err = sshClient.Dial(network, addr)
				if err == nil {
					break
				}
				updateLog(fmt.Sprintf("⚠️ Attempt %d failed: %v", i+1, err))
				time.Sleep(1 * time.Second)
			}
			if err != nil {
				updateLog(fmt.Sprintf("❌ Failed to tunnel %s after 3 attempts: %v", addr, err))
				return nil, err
			}
			updateLog(fmt.Sprintf("✅ Successfully tunneled %s", addr))
			return conn, nil
		},
		Resolver: noOpResolver,
	}

	// Create SOCKS5 server
	socksServer, err = socks5.New(socks5Conf)
	if err != nil {
		updateLog(fmt.Sprintf("❌ Failed to create SOCKS5 server: %v", err))
		return
	}

	// Start SOCKS5 server
	socksAddr := fmt.Sprintf("127.0.0.1:%s", socksPort)
	updateLog(fmt.Sprintf("🚀 SOCKS5 server started at %s (DNS resolving disabled)", socksAddr))

	stopChan = make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := socksServer.ListenAndServe("tcp", socksAddr); err != nil {
			updateLog(fmt.Sprintf("❌ SOCKS5 server failed: %v", err))
		}
	}()

	// Enable/disable buttons
	connectBtn.Disable()
	disconnectBtn.Enable()
}

func stopTunnel() {
	mu.Lock()
	defer mu.Unlock()

	if running {
		if sshClient != nil {
			sshClient.Close()
			updateLog("🔌 SSH tunnel disconnected")
			sshClient = nil
		}
		if stopChan != nil {
			close(stopChan)
			wg.Wait()
			updateLog("🔌 SOCKS5 server stopped")
			stopChan = nil
		}
		running = false
	}
	// Enable/disable buttons
	connectBtn.Enable()
	disconnectBtn.Disable()
}

type NoOpResolver struct{}

func (r *NoOpResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	updateLog(fmt.Sprintf("🔧 Resolving disabled for %s, forwarding raw domain", name))
	return ctx, nil, nil
}

func updateLog(message string) {
	log.Println(message)
	logText.SetText(logText.Text + message + "\n")
	logText.Refresh()
}

func loadConfig() (Config, error) {
	configFile := "config.json"
	var config Config
	data, err := os.ReadFile(configFile)
	if err != nil {
		return Config{}, nil // Return empty config if file doesn't exist
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return Config{}, fmt.Errorf("failed to parse config file: %v", err)
	}
	return config, nil
}

func saveConfig(config Config) error {
	configFile := "config.json"
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}
	return os.WriteFile(configFile, data, 0644)
}

func encryptPassword(password string) (string, error) {
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	padding := aes.BlockSize - len(password)%aes.BlockSize
	padText := append([]byte(password), byte(padding))
	for i := 1; i < padding; i++ {
		padText = append(padText, byte(padding))
	}
	ciphertext := make([]byte, aes.BlockSize+len(padText))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], padText)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptPassword(encrypted string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", err
	}
	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)
	padding := int(ciphertext[len(ciphertext)-1])
	if padding > len(ciphertext) || padding > aes.BlockSize {
		return "", fmt.Errorf("invalid padding")
	}
	return string(ciphertext[:len(ciphertext)-padding]), nil
}
