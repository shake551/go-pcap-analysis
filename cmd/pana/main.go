package main

import (
	"encoding/json"
	"flag"
	"github.com/shake551/go-pcap-analysis"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

func main() {
	s := time.Now()

	f := flag.String("f", "", "file path")
	fromOtherIP := flag.String("from-other-ip", "", "filter from outside only")

	flag.Parse()

	if *f == "" {
		log.Fatal("no file path")
	}

	dir, inputFile := filepath.Split(*f)
	var files []fs.FileInfo
	if inputFile == "" {
		files, _ = ioutil.ReadDir(dir)
	} else {
		fileSystem := os.DirFS(dir)
		fileInfo, err := fs.Stat(fileSystem, inputFile)
		if err != nil {
			log.Fatal(err)
		}
		files = append(files, fileInfo)
	}

	var wg sync.WaitGroup

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		filePath := filepath.Join(dir, file.Name())

		wg.Add(1)
		go func(filePath string, wg *sync.WaitGroup) {
			defer wg.Done()

			queryLogs := query.GetDNSQueryLogs(filePath, *fromOtherIP)

			_, file := filepath.Split(filePath)
			fileName := strings.Split(file, ".")[0]

			qj, err := json.Marshal(queryLogs)
			if err != nil {
				log.Printf("failed to parse json. err: %v", err)
			}
			fp, err := os.Create("json/" + fileName + "_created_" + time.Now().Format(time.RFC3339) + ".json")
			if err != nil {
				log.Fatal(err)
			}
			fp.Write(qj)

			csvContent := query.ToCSV(queryLogs)
			csvf, err := os.Create("csv/" + fileName + "_created_" + time.Now().Format(time.RFC3339) + ".csv")
			if err != nil {
				log.Fatal(err)
			}
			csvf.WriteString(csvContent.String())
			log.Println("create log file")
		}(filePath, &wg)
	}

	wg.Wait()

	log.Println("finish")
	e := time.Now()
	log.Printf("処理秒数: %v\n", e.Sub(s).Round(time.Second))
}
