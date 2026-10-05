// eventbus_bindings.go — adapters that project eventbus deliveries onto the
// identity subscriber methods. Kept separate from the subscribers so the
// domain-facing Handle* methods stay transport-agnostic.
package events

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/apollo-chora/chora-common/eventbus"
	paymentsv1 "github.com/apollo-chora/chora-contracts/gen/go/chora/payments/v1"
)

// UserManaTopUpHandler adapts the UserManaTopUpSubscriber to an
// eventbus.Handler. chora-payments publishes the capture as Protobuf wire
// bytes, so the payload is proto.Unmarshal'd into the generated type.
func UserManaTopUpHandler(s *UserManaTopUpSubscriber) eventbus.Handler {
	return func(ctx context.Context, msg eventbus.Message) error {
		if s == nil {
			return errors.New("events: user_mana_topup handler not initialised")
		}
		var ev paymentsv1.UserManaTopUpPaymentCaptured
		if err := proto.Unmarshal(msg.Payload, &ev); err != nil {
			return fmt.Errorf("events: user_mana_topup payload decode: %w", err)
		}
		return s.HandlePaymentCaptured(ctx, &ev)
	}
}
