package modules

import (
	"log"
	"my-bpf/config"
	"strings"
	"time"

	"github.com/Shopify/sarama"
)

type IEventHandler interface {
	Init(c *config.Configuration)
	POSTMessage(b []byte)
}

type EventHandler struct {
	coreHandler IEventHandler
}

type ConsoleHandler struct {
}

func (ch *ConsoleHandler) Init(c *config.Configuration) {
}

func (ch *ConsoleHandler) POSTMessage(b []byte) {
	log.Println(string(b))
}

type KafkaHandler struct {
	KafkaAddr   string
	KafkaTopic  string
	KafkaClient sarama.SyncProducer
}

func (kh *KafkaHandler) Init(c *config.Configuration) {
	var err error
	kh.KafkaAddr = c.KafkaAddr
	kh.KafkaTopic = c.KafkaTopic
	config := sarama.NewConfig()
	config.Producer.RequiredAcks = sarama.WaitForAll
	config.Producer.Partitioner = sarama.NewRandomPartitioner
	config.Producer.Return.Successes = true
	config.Producer.Return.Errors = true
	config.Producer.Timeout = time.Second * 5
	kh.KafkaClient, err = sarama.NewSyncProducer(strings.Split(c.KafkaAddr, ","), config)
	if err != nil {
		log.Printf("init kafka client error: %v", err)
	}
}

func (kh *KafkaHandler) POSTMessage(b []byte) {
	if kh.KafkaClient == nil {
		return
	}
	msg := &sarama.ProducerMessage{
		Topic: kh.KafkaTopic,
		Value: sarama.ByteEncoder(b),
	}
	kh.KafkaClient.SendMessage(msg)
}

func NewEventHandler(c *config.Configuration) *EventHandler {
	h := &EventHandler{}
	if c.EventOutput == "Kafka" {
		log.Println("init kafka event handler")
		h.coreHandler = &KafkaHandler{}
	} else {
		log.Println("init console event handler")
		h.coreHandler = &ConsoleHandler{}
	}
	h.coreHandler.Init(c)
	return h
}

func (eh *EventHandler) POSTMessage(b []byte) {
	eh.coreHandler.POSTMessage(b)
}
