package eventupload

// ForwardedEventUploadEvent is a single event entry that appends the MachineID with the EventUploadEvent details
// and is send to Firehose
type ForwardedEventUploadEvent struct {
	MachineID string `json:"machine_id"`
	EventUploadEvent
}

func convertRequestEventsToUploadEvents(machineID string, events []EventUploadEvent) []interface{} {
	var forwardedEvents []interface{}

	for _, event := range events {
		forwardedEvents = append(forwardedEvents, ForwardedEventUploadEvent{
			MachineID:        machineID,
			EventUploadEvent: event,
		})
	}

	return forwardedEvents
}

// ForwardedFileAccessEvent wraps a FileAccessEvent with machine context for Lambda delivery.
type ForwardedFileAccessEvent struct {
	EventType string `json:"event_type"`
	MachineID string `json:"machine_id"`
	FileAccessEvent
}

func convertFileAccessEventsToUploadEvents(machineID string, events []FileAccessEvent) []interface{} {
	var forwardedEvents []interface{}

	for _, event := range events {
		forwardedEvents = append(forwardedEvents, ForwardedFileAccessEvent{
			EventType:       "file_access",
			MachineID:       machineID,
			FileAccessEvent: event,
		})
	}

	return forwardedEvents
}
