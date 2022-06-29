package main

import (
	"crypto/sha256"
    "fmt"
    "os"
	"log"
	"io"
    "path/filepath"
	"encoding/hex"
	"encoding/csv"
	"time"
	"strconv"
)

func showHelp() {
	fmt.Println("Help menu:\n\n-h Show help menu.\n-b baseline scan.\n-s hash scan.\n-ts timed hash scan.\n")
	fmt.Println("Usage: go go-watcher.go <scan type> <scan directory> <scan file directory> <time interval for timed scans> <number of timed scans>\n")
	fmt.Println("Explanation:\n\nFirstly, do a baseline scan on the directory. It will store the hashes of its files.")
	fmt.Println("At this point you can do hash scans to check if any of those files have been tampered")
}

func writeToFile(files []string, hashes []string, outDirectory string) {
	
	var fileHashArray = [][]string{files, hashes}

	baseScan, err := os.Create(outDirectory+"/baseScan.csv")
	if err != nil {
		log.Fatal(err)
	}
	defer baseScan.Close()

	writer := csv.NewWriter(baseScan)
	defer writer.Flush()

	for _, value := range fileHashArray {
        err := writer.Write(value)
        if err != nil {
			log.Fatal(err)
		}
    }

	fmt.Println(fileHashArray[1][0])
}
	

func hashFiles(files []string) []string {

	var hashes []string

	for _,file := range files {
		f, err := os.Open(file)

		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		hash := sha256.New()
		if _, err := io.Copy(hash, f); err != nil {
			log.Fatal(err)
		}

		hashes = append(hashes, hex.EncodeToString(hash.Sum(nil)))
	}

	return hashes
}

func getFiles(directory string) []string {
	var files []string

    err := filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		info, statErr := os.Stat(path)
		if err != nil {
			log.Fatal(statErr)
		}
		if info.IsDir() {
			fmt.Println("[+] Found directory: ", path)
		} else {
			files = append(files, path)
		}
        return nil
    })
    if err != nil {
        panic(err)
    }
    for _, file := range files {
        fmt.Println("[+] Found file: ", file)
    }

	return files
}

func baselineScan(directory string, outDirectory string) {
	var files []string
	var hashes []string

	fmt.Println("[+] Getting files in the directory...")
	files = getFiles(directory)
	fmt.Println("[+] Hashing the files...")
	hashes = hashFiles(files)
	
	writeToFile(files, hashes, outDirectory)
}

func readBaselineScan(outDirectory string) [][]string {

	file, err := os.Open(outDirectory+"/baseScan.csv")
	if err != nil {
        log.Fatal(err)
    }
    defer file.Close()

    csvReader := csv.NewReader(file)
    data, err := csvReader.ReadAll()
    if err != nil {
        log.Fatal(err)
    }

	return data
}

func compareHashes(directory string, outDirectory string) {

	fmt.Println("[+] Reading the baseline scan...")
	var fileHashArray = readBaselineScan(outDirectory)

	var files []string
	var hashes []string

	fmt.Println("[+] Getting files in the directory...")
	files = getFiles(directory)
	fmt.Println("[+] Hashing the files...")
	hashes = hashFiles(files)

	fmt.Println("[+] Scanning...")
	for i := 0; i < len(files)-1; i++ {
		if fileHashArray[1][i] != hashes[i] {
				fmt.Println("\n[!] Tampered file found: ", files[i])
				fmt.Println("[!] Original hash: ", hashes[i])
				fmt.Println("[!] New hash: ", fileHashArray[1][i])
				fmt.Println("")
				if files[i] != outDirectory+"\\baseScan.csv" { //Change this to '/baseScan.csv' on Unix systems.
					fmt.Println("[-] This might be a false positive if the file is properly restricted.\n")
				}
		}
	}
}

func timedCompare(directory string, interval int, iterations int, outDirectory string) {
	baselineScan(directory, outDirectory)
	for i := 0; i < iterations; i++ {
		compareHashes(directory, outDirectory)
		fmt.Println("[+] Sleeping...\n\n")
		time.Sleep(time.Duration(interval) * time.Second)
	}
}

func main() {

	if(len(os.Args) < 2 || len(os.Args) > 6) {
		showHelp()
		return
	}

	scanType := os.Args[1] 

	if os.Args[1] != "-h" {

		scanDirectory := os.Args[2]
		outDirectory := os.Args[3]
		switch scanType{
		case "-b":
			baselineScan(scanDirectory, outDirectory)
			fmt.Println("[+] Baseline scan completed (results saved)!\n")
		case "-s":
			compareHashes(scanDirectory, outDirectory)
			fmt.Println("[+] Hash comparison completed!\n")
			fmt.Println("[+] Make sure you reduce false positives by not creating or changing any files after the baseline scan.\n")
		case "-ts":
			interval,_ := strconv.Atoi(os.Args[4])
			iterations,_ := strconv.Atoi(os.Args[5])
			timedCompare(scanDirectory, interval, iterations, outDirectory)
			fmt.Println("[+] Exited timed scan!")
		} 
	}else if os.Args[1] == "-h" {
		showHelp()
	} else {
		fmt.Println("[-] Invalid arguments!\n")
		showHelp()
	}
}