module simulate_target_device

go 1.21

require (
	github.com/brocaar/chirpstack-simulator v0.0.0
	github.com/brocaar/lorawan v0.0.0-20191105091820-9ed596703a6c
	github.com/chirpstack/chirpstack/api/go/v4 v4.0.0-rc.2
	github.com/gofrs/uuid v3.2.0+incompatible
	github.com/sirupsen/logrus v1.4.2
	google.golang.org/grpc v1.45.0
)

replace github.com/brocaar/chirpstack-simulator => /home/jonas/Downloads/chirpstack-simulator
