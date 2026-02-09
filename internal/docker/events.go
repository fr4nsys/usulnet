// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package docker

import (
	"context"
	"fmt"
	"time"

	dockerevents "github.com/docker/docker/api/types/events"
)

// DockerEvent represents a Docker engine event in a simplified form.
type DockerEvent struct {
	Type      string    // container, image, network, volume, etc.
	Action    string    // start, stop, create, die, pull, etc.
	ActorID   string    // Container/Image/Network/Volume ID
	ActorName string    // Name from attributes
	Time      time.Time // When the event occurred
}

// GetEvents returns recent Docker events since the given time.
func (c *Client) GetEvents(ctx context.Context, since time.Time) ([]DockerEvent, error) {
	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.RUnlock()

	// Use a timeout context to avoid hanging
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	opts := dockerevents.ListOptions{
		Since: fmt.Sprintf("%d", since.Unix()),
		Until: fmt.Sprintf("%d", time.Now().Unix()),
	}

	msgCh, errCh := c.cli.Events(ctx, opts)

	var events []DockerEvent
	for {
		select {
		case msg, ok := <-msgCh:
			if !ok {
				return events, nil
			}
			events = append(events, convertDockerEvent(msg))
		case err := <-errCh:
			if err != nil && err != context.DeadlineExceeded {
				return events, err
			}
			return events, nil
		case <-ctx.Done():
			return events, nil
		}
	}
}

// StreamEvents returns a channel of live Docker events.
func (c *Client) StreamEvents(ctx context.Context) (<-chan DockerEvent, <-chan error) {
	eventCh := make(chan DockerEvent, 64)
	outErrCh := make(chan error, 1)

	c.mu.RLock()
	if c.closed {
		c.mu.RUnlock()
		close(eventCh)
		outErrCh <- fmt.Errorf("client is closed")
		return eventCh, outErrCh
	}
	c.mu.RUnlock()

	opts := dockerevents.ListOptions{}
	msgCh, dockerErrCh := c.cli.Events(ctx, opts)

	go func() {
		defer close(eventCh)
		for {
			select {
			case msg, ok := <-msgCh:
				if !ok {
					return
				}
				select {
				case eventCh <- convertDockerEvent(msg):
				case <-ctx.Done():
					return
				}
			case err := <-dockerErrCh:
				if err != nil {
					select {
					case outErrCh <- err:
					default:
					}
				}
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	return eventCh, outErrCh
}

func convertDockerEvent(msg dockerevents.Message) DockerEvent {
	name := msg.Actor.Attributes["name"]
	if name == "" {
		name = msg.Actor.ID
		if len(name) > 12 {
			name = name[:12]
		}
	}

	var t time.Time
	if msg.TimeNano > 0 {
		t = time.Unix(0, msg.TimeNano)
	} else if msg.Time > 0 {
		t = time.Unix(msg.Time, 0)
	} else {
		t = time.Now()
	}

	return DockerEvent{
		Type:      string(msg.Type),
		Action:    string(msg.Action),
		ActorID:   msg.Actor.ID,
		ActorName: name,
		Time:      t,
	}
}
