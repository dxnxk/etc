package graylog

import (
        //      "flag"
        "fmt"
        "github.com/moira-alert/moira"
        "gopkg.in/Graylog2/go-gelf.v2/gelf"
        //      "io"
        //      "log"
//      "os"
        "strconv"
        "time"
        "encoding/json"
        "github.com/ShowMax/go-fqdn"
)

// Sender implements moira sender interface
type Sender struct {
        GraylogHost string
        FrontURI string
        log         moira.Logger
        //      Template    *template.Template
        location *time.Location
}

type templateRow struct {
        Metric     string
        Timestamp  string
        Oldstate   string
        State      string
        Value      string
        WarnValue  string
        ErrorValue string
        Message    string
}

// Init read yaml config
func (sender *Sender) Init(senderSettings map[string]string, logger moira.Logger, location *time.Location) error {
        sender.setLogger(logger)
        sender.GraylogHost = senderSettings["graylog_host"]
        sender.FrontURI = senderSettings["front_uri"]
        sender.location = location

        return nil
}

// SendEvents implements Sender interface Send
func (sender *Sender) SendEvents(events moira.NotificationEvents, contact moira.ContactData, trigger moira.TriggerData, throttled bool) error {

        state := events.GetSubjectState()
        tags := trigger.GetTags()

        subject := fmt.Sprintf("%s %s %s (%d)", state, trigger.Name, tags, len(events))

        templateData := struct {
                Link        string
                Description string
                Throttled   bool
                Items       []*templateRow
        }{
                Link:        fmt.Sprintf("%s/trigger/%s", sender.FrontURI, events[0].TriggerID),
                Description: trigger.Desc,
                Throttled:   throttled,
                Items:       make([]*templateRow, 0, len(events)),
        }

        for _, event := range events {
                templateData.Items = append(templateData.Items, &templateRow{
                        Metric:     event.Metric,
                        Timestamp:  time.Unix(event.Timestamp, 0).In(sender.location).Format("15:04 02.01.2006"),
                        Oldstate:   event.OldState,
                        State:      event.State,
                        Value:      strconv.FormatFloat(moira.UseFloat64(event.Value), 'f', -1, 64),
                        WarnValue:  strconv.FormatFloat(trigger.WarnValue, 'f', -1, 64),
                        ErrorValue: strconv.FormatFloat(trigger.ErrorValue, 'f', -1, 64),
                        Message:    moira.UseString(event.Message),
                })
        }

/////////////////////////////////////////////////////////////////////////
        message, err := json.Marshal(templateData)
        if err != nil {
                panic(err)
        }

        severity := map[string]int32{
            "OK":       5,
            "WARN":     4,
            "CRIT":     2,
            "NODATA":   3,
            "ERROR":    3,
            "TEST":     6,
        }

/////////////////////////////////////////////////////////////////////////
        glf, err := gelf.NewUDPWriter(sender.GraylogHost)
        if err != nil {
                return err
        }
        msg := gelf.Message{
                Version: "1.1",
                Host:    fmt.Sprintln(fqdn.Get()),
                Short:   subject,
                Full:    string(message),
                Level:   severity[state],
        }
        if err := glf.WriteMessage(&msg); err != nil {
                return err
        }
        return nil
}

func (sender *Sender) setLogger(logger moira.Logger) {
        sender.log = logger
}
