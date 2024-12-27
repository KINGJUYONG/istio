package main

import (
	"bufio"
	"fmt"
	"github.com/fsnotify/fsnotify"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const (
	configPath     = "/etc/cryptoflex.conf"
	pilotAgentPath = "/usr/local/pilot-agent"
	
	// BSSL libraries
	bsslLibSSL    = "/usr/local/bssl-compat/lib64/b_libssl.so"
	bsslLibCrypto = "/usr/local/bssl-compat/lib64/b_libcrypto.so"
	
	// OSSL library
	osslPath      = "/usr/local/bssl-compat/lib64/libbssl-compat.so"
)

type ConfigWatcher struct {
	watcher *fsnotify.Watcher
	mu      sync.Mutex
}

func NewConfigWatcher() (*ConfigWatcher, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %v", err)
	}

	return &ConfigWatcher{
		watcher: watcher,
	}, nil
}

func (cw *ConfigWatcher) Start() error {
	defer cw.watcher.Close()

	// Add the configuration file to watch
	if err := cw.watcher.Add(configPath); err != nil {
		return fmt.Errorf("failed to add watch for %s: %v", configPath, err)
	}

	// Initial read of config
	if err := cw.handleConfigChange(); err != nil {
		log.Printf("Initial config read failed: %v", err)
	}

	for {
		select {
		case event, ok := <-cw.watcher.Events:
			if !ok {
				return fmt.Errorf("watcher event channel closed")
			}
			if event.Op&fsnotify.Write == fsnotify.Write {
				if err := cw.handleConfigChange(); err != nil {
					log.Printf("Failed to handle config change: %v", err)
				}
			}
		case err, ok := <-cw.watcher.Errors:
			if !ok {
				return fmt.Errorf("watcher error channel closed")
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

func (cw *ConfigWatcher) handleConfigChange() error {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	// Read configuration safely
	config, err := readConfig()
	if err != nil {
		return fmt.Errorf("failed to read config: %v", err)
	}

	// Determine which library to preload
	var ldPreloadPaths []string
	switch strings.TrimSpace(strings.ToLower(config)) {
	case "bssl":
		ldPreloadPaths = []string{bsslLibSSL, bsslLibCrypto}
	case "ossl":
		ldPreloadPaths = []string{osslPath}
	default:
		return fmt.Errorf("invalid configuration value: %s", config)
	}

	// Verify pilot-agent exists and is executable
	if err := verifyExecutable(pilotAgentPath); err != nil {
		return fmt.Errorf("pilot-agent verification failed: %v", err)
	}

	// Launch the process
	if err := launchProcess(ldPreloadPath); err != nil {
		return fmt.Errorf("failed to launch process: %v", err)
	}

	return nil
}

func readConfig() (string, error) {
	// Verify the path is not a symlink to prevent TOCTOU attacks
	realPath, err := filepath.EvalSymlinks(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve config path: %v", err)
	}

	file, err := os.Open(realPath)
	if err != nil {
		return "", fmt.Errorf("failed to open config: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("failed to read config: %v", err)
		}
		return "", fmt.Errorf("config file is empty")
	}

	return scanner.Text(), nil
}

func verifyExecutable(path string) error {
	// Resolve any symlinks
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("failed to resolve path: %v", err)
	}

	// Verify file exists and is executable
	info, err := os.Stat(realPath)
	if err != nil {
		return fmt.Errorf("failed to stat file: %v", err)
	}

	if info.Mode()&0111 == 0 {
		return fmt.Errorf("file is not executable")
	}

	return nil
}

func launchProcess(ldPreloadPath string) error {
	// Get current environment and modify it
	env := os.Environ()
	
	// Update or add LD_PRELOAD
	var currentPreloads []string
	ldPreloadIndex := -1
	
	// Find existing LD_PRELOAD if any
	for i, e := range env {
		if strings.HasPrefix(e, "LD_PRELOAD=") {
			ldPreloadIndex = i
			currentValue := strings.TrimPrefix(e, "LD_PRELOAD=")
			if currentValue != "" {
				currentPreloads = strings.Split(currentValue, ":")
			}
			break
		}
	}
	
	// Add new libraries to preload list
	currentPreloads = append(currentPreloads, ldPreloadPaths...)
	
	// Create new LD_PRELOAD value
	newLDPreload := fmt.Sprintf("LD_PRELOAD=%s", strings.Join(currentPreloads, ":"))
	
	if ldPreloadIndex >= 0 {
		// Update existing LD_PRELOAD
		env[ldPreloadIndex] = newLDPreload
	} else {
		// Add new LD_PRELOAD
		env = append(env, newLDPreload)
	}

	// Use Command instead of CommandContext to avoid shell injection
	cmd := exec.Command(pilotAgentPath)
	cmd.Env = env
	
	// Set up logging for stdout and stderr
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %v", err)
	}

	// Don't wait for the process to complete as it may be long-running
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("Process exited with error: %v", err)
		}
	}()

	return nil
}

func main() {
	watcher, err := NewConfigWatcher()
	if err != nil {
		log.Fatalf("Failed to create watcher: %v", err)
	}

	log.Printf("Starting config watcher for %s", configPath)
	if err := watcher.Start(); err != nil {
		log.Fatalf("Watcher failed: %v", err)
	}
}