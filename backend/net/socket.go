package net

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/nist"
	"gopkg.in/dedis/crypto.v0/proof"

	"github.com/qantik/evo/backend/crypto/elgamal"
	"github.com/qantik/evo/backend/crypto/neff"
	"github.com/qantik/evo/backend/crypto/sato"
)

// Base backend structure comprising all necessary fields
// to run a concurrent HTTP server with websocket channels.
type Server struct {
	root      http.Handler
	clients   map[*websocket.Conn]bool
	broadcast chan query
	upgrader  websocket.Upgrader
}

type query struct {
	Votes       []string `json: "votes"`
	Algorithm   string   `json: "algorithm"`
	Parallelize bool     `json: "parallelize"`
}

type response struct {
	Time string `json: "time"`
}

// Create an ElGamal encryption pair for each data string object.
func encrypt(suite abstract.Suite, data []string, stream abstract.Cipher) (
	A, B []abstract.Point) {

	k := len(data)
	A = make([]abstract.Point, k)
	B = make([]abstract.Point, k)

	for i := 0; i < k; i++ {
		secret := suite.Scalar().Pick(stream)
		public := suite.Point().Mul(nil, secret)

		alpha, beta := elgamal.Encrypt(suite, public, []byte(data[i]))
		A[i] = alpha
		B[i] = beta
	}

	return
}

func verifyNeff(suite abstract.Suite, A, B []abstract.Point, stream abstract.Cipher) {
	Ap, Bp, prover := neff.Shuffle(suite, nil, nil, A, B, stream)
	stamp, _ := proof.HashProve(suite, "PS", stream, prover)

	verifier := neff.Verifier(suite, nil, nil, A, B, Ap, Bp)
	_ = proof.HashVerify(suite, "PS", verifier, stamp)
}

func verifySato(wg *sync.WaitGroup, p bool, suite abstract.Suite, A, B []abstract.Point,
	stream abstract.Cipher) {

	if p {
		defer wg.Done()
	}

	Ap, Bp, prover := sato.Shuffle(suite, nil, nil, A, B, stream)
	stamp, _ := proof.HashProve(suite, "SK", stream, prover)

	verifier := sato.Verifier(suite, nil, nil, A, B, Ap, Bp)
	_ = proof.HashVerify(suite, "SK", verifier, stamp)
}

// Register incoming new websocket connections and parse potential queries from
// the channels before piping them to the broadcaster.
func (server *Server) connection(w http.ResponseWriter, r *http.Request) {
	ws, err := server.upgrader.Upgrade(w, r, nil)
	if err != nil {
		panic("Upgrading TCP to WS failed")
	}
	defer ws.Close()

	server.clients[ws] = true

	var msg query
	for {
		if err := ws.ReadJSON(&msg); err != nil {
			delete(server.clients, ws)
			break
		}
		server.broadcast <- msg
	}
}

// Process and distribute incoming queries from the broadcaster.
func (server *Server) distribute() {
	for {
		msg := <-server.broadcast

		suite := nist.NewAES128SHA256P256()
		stream := suite.Cipher(abstract.RandomKey)

		A, B := encrypt(suite, msg.Votes, stream)

		var wg sync.WaitGroup
		start := time.Now()
		if msg.Algorithm == "neff" {
			verifyNeff(suite, A, B, stream)
		} else {
			for i := 0; i < 80; i++ {
				if msg.Parallelize {
					wg.Add(1)
					go verifySato(&wg, true, suite, A, B, stream)
				} else {
					verifySato(&wg, false, suite, A, B, stream)
				}
			}
		}
		wg.Wait()
		elapsed := time.Since(start)

		for client := range server.clients {
			if client.WriteJSON(elapsed.String()) != nil {
				client.Close()
				delete(server.clients, client)
			}
		}
	}
}

// Creation of HTTP server and its respective websockets with listening
// at the provided root directory.
func Open(root string) *Server {
	server := new(Server)
	server.root = http.FileServer(http.Dir(root))
	server.clients = make(map[*websocket.Conn]bool)
	server.broadcast = make(chan query)
	server.upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}

	http.Handle("/", server.root)
	http.HandleFunc("/ws", server.connection)

	go server.distribute()

	fmt.Println("Server listening on port 8000")
	if err := http.ListenAndServe("localhost:8000", nil); err != nil {
		panic(err)
	}

	return server
}
