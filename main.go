package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"firestoresubmitter/gsa"
)

type Server struct {
	gsa            *gsa.Gsa
	token          string
	tokenExpiresAt int64
	dataChannel    chan string
}

const firestoreDataStr = `{"fields":{"temp":{"stringValue":"%s"},"hum":{"stringValue":"%s"}}}`
const firestoreURL = "https://firestore.googleapis.com/v1/projects/para-a2923/databases/(default)/documents/adatok/ylsKyIZTUr5uEFDy8Bta"

func (s *Server) postSubmit(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		fmt.Println(err)
	}

	bodyStr := string(body)
	values := strings.Split(bodyStr, ";")
	if len(values) != 2 {
		w.WriteHeader(400)
		io.WriteString(w, "Invalid format\n")
		return
	}
	io.WriteString(w, "OK\n")
	s.dataChannel <- bodyStr
}

func (s *Server) refreshToken() error {
	token, err := s.gsa.GetServiceToken()
	if err != nil {
		fmt.Println("Could not refresh service token")
		return err
	}
	s.tokenExpiresAt = time.Now().Unix() + token.ExpiresIn
	s.token = token.Token
	return nil
}

func (s *Server) submit(data string) {
	slice := strings.Split(data, ";")
	body := fmt.Sprintf(firestoreDataStr, slice[0], slice[1])
	req, err := http.NewRequest("PATCH", firestoreURL, strings.NewReader(body))
	if err != nil {
		fmt.Println(err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+s.token)
	c := &http.Client{}
	resp, err := c.Do(req)
	if err != nil {
		fmt.Println(err)
		return
	}
	if resp.StatusCode != 200 {
		fmt.Println("Could not send to firestore")
		return
	}
	fmt.Println(time.Now().Format("2006.01.02-15:04:05"), "Data sent")
}

func main() {
	gsa, err := gsa.UseJson("account.json", "https://www.googleapis.com/auth/datastore")
	if err != nil {
		fmt.Println(err)
		return
	}

	dataChannel := make(chan string, 1)

	server := Server{
		gsa:         gsa,
		dataChannel: dataChannel,
	}

	go func() {
		for {
			data := <-dataChannel
			if server.tokenExpiresAt < time.Now().Unix()+5 {
				if err := server.refreshToken(); err != nil {
					time.Sleep(5 * time.Second)
					continue
				}
			}
			server.submit(data)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/submit", server.postSubmit)
	port := os.Getenv("SUBMITTER_PORT")
	if _, err := strconv.Atoi(port); err != nil {
		port = "80"
	}
	address := "0.0.0.0" + ":" + port
	err = http.ListenAndServe(address, mux)
	if err != nil {
		fmt.Println(err)
	}
}
