package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/brocaar/chirpstack-simulator/simulator"
	"github.com/brocaar/lorawan"
	"github.com/chirpstack/chirpstack/api/go/v4/api"
	"github.com/chirpstack/chirpstack/api/go/v4/common"
	"github.com/chirpstack/chirpstack/api/go/v4/gw"
	"github.com/gofrs/uuid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
)

type jwtCredentials struct {
	token string
}

func (j *jwtCredentials) GetRequestMetadata(ctx context.Context, url ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + j.token,
	}, nil
}

func (j *jwtCredentials) RequireTransportSecurity() bool {
	return false
}

func main() {
	// Flags (Read secrets from environment variables with empty default fallbacks)
	server := flag.String("server", "127.0.0.1:8080", "ChirpStack API server address")
	apiKey := flag.String("api-key", os.Getenv("CHIRPSTACK_API_KEY"), "ChirpStack API Key (or set CHIRPSTACK_API_KEY env var)")
	tenantID := flag.String("tenant-id", os.Getenv("CHIRPSTACK_TENANT_ID"), "ChirpStack Tenant ID (or set CHIRPSTACK_TENANT_ID env var)")
	mqttBroker := flag.String("mqtt-broker", "tcp://127.0.0.1:1883", "MQTT Broker URL")

	// Target matching interceptor defaults (randomized realistic identifiers)
	gatewayIDHex := flag.String("gateway-id", "d98812585f1f4c5f", "Gateway ID Hex (8 bytes)")
	devEUIHex := flag.String("dev-eui", "07467874f27834b8", "Device EUI Hex (8 bytes)")
	appKeyHex := flag.String("app-key", "07dbdb82e850f8aa25e274d1632fa51b", "AppKey Hex (16 bytes)")
	uplinkCount := flag.Uint("uplink-count", 3, "Number of uplinks after OTAA activation")
	autoRegister := flag.Bool("register", true, "Automatically register Gateway, DeviceProfile, Application, and Device in ChirpStack")

	flag.Parse()

	log.SetLevel(log.InfoLevel)
	log.Info("=== Starting ChirpStack Target Device Simulation ===")
	log.Infof("DevEUI    : %s", *devEUIHex)
	log.Infof("AppKey    : %s", *appKeyHex)
	log.Infof("GatewayID : %s", *gatewayIDHex)

	var gwEUI lorawan.EUI64
	var devEUI lorawan.EUI64
	var appKey lorawan.AES128Key

	if err := gwEUI.UnmarshalText([]byte(*gatewayIDHex)); err != nil {
		log.Fatalf("invalid gateway ID: %s", err)
	}
	if err := devEUI.UnmarshalText([]byte(*devEUIHex)); err != nil {
		log.Fatalf("invalid dev EUI: %s", err)
	}
	if err := appKey.UnmarshalText([]byte(*appKeyHex)); err != nil {
		log.Fatalf("invalid app key: %s", err)
	}

	ctx := context.Background()

	if *autoRegister {
		log.Info("Registering Gateway, DeviceProfile, Application, and Device via ChirpStack gRPC API...")
		if err := registerInChirpStack(ctx, *server, *apiKey, *tenantID, gwEUI, devEUI, appKey); err != nil {
			log.Warnf("Registration warning (continuing if entities already exist): %v", err)
		}
	}

	// Setup Gateway over MQTT
	sgw, err := simulator.NewGateway(
		simulator.WithMQTTCredentials(*mqttBroker, "", ""),
		simulator.WithGatewayID(gwEUI),
		simulator.WithEventTopicTemplate("eu868/gateway/{{ .GatewayID }}/event/{{ .Event }}"),
		simulator.WithCommandTopicTemplate("eu868/gateway/{{ .GatewayID }}/command/{{ .Command }}"),
	)
	if err != nil {
		log.Fatalf("failed to create simulated gateway: %v", err)
	}

	var wg sync.WaitGroup
	log.Info("Starting Simulated Device (OTAA join procedure)...")

	_, err = simulator.NewDevice(ctx, &wg,
		simulator.WithDevEUI(devEUI),
		simulator.WithAppKey(appKey),
		simulator.WithRandomDevNonce(),
		simulator.WithUplinkInterval(5*time.Second),
		simulator.WithUplinkCount(uint32(*uplinkCount)),
		simulator.WithUplinkPayload(false, 10, []byte{0x01, 0x02, 0x03}),
		simulator.WithUplinkTXInfo(gw.UplinkTxInfo{
			Frequency: 868100000,
			Modulation: &gw.Modulation{
				Parameters: &gw.Modulation_Lora{
					Lora: &gw.LoraModulationInfo{
						Bandwidth:       125000,
						SpreadingFactor: 7,
						CodeRate:        gw.CodeRate_CR_4_5,
					},
				},
			},
		}),
		simulator.WithGateways([]*simulator.Gateway{sgw}),
		simulator.WithDownlinkHandlerFunc(func(conf, ack bool, fCntDown uint32, fPort uint8, data []byte) error {
			log.WithFields(log.Fields{
				"ack":       ack,
				"fcnt_down": fCntDown,
				"f_port":    fPort,
				"data":      hex.EncodeToString(data),
			}).Info("Simulated device received downlink data")
			return nil
		}),
	)
	if err != nil {
		log.Fatalf("failed to create simulated device: %v", err)
	}

	wg.Wait()
	log.Info("Simulation complete.")
}

func registerInChirpStack(ctx context.Context, server, apiKey, tenantID string, gwEUI, devEUI lorawan.EUI64, appKey lorawan.AES128Key) error {
	dialOpts := []grpc.DialOption{
		grpc.WithBlock(),
		grpc.WithPerRPCCredentials(&jwtCredentials{token: apiKey}),
		grpc.WithInsecure(),
	}

	conn, err := grpc.DialContext(ctx, server, dialOpts...)
	if err != nil {
		return fmt.Errorf("grpc dial error: %w", err)
	}
	defer conn.Close()

	gwClient := api.NewGatewayServiceClient(conn)
	dpClient := api.NewDeviceProfileServiceClient(conn)
	appClient := api.NewApplicationServiceClient(conn)
	devClient := api.NewDeviceServiceClient(conn)

	// 1. Gateway
	_, _ = gwClient.Create(ctx, &api.CreateGatewayRequest{
		Gateway: &api.Gateway{
			GatewayId:   gwEUI.String(),
			Name:        "sim-gateway-" + gwEUI.String(),
			Description: "Simulated Gateway",
			TenantId:    tenantID,
			Location:    &common.Location{},
		},
	})

	// 2. Device Profile
	dpName, _ := uuid.NewV4()
	dpResp, err := dpClient.Create(ctx, &api.CreateDeviceProfileRequest{
		DeviceProfile: &api.DeviceProfile{
			Name:              "profile-" + dpName.String(),
			TenantId:          tenantID,
			MacVersion:        common.MacVersion_LORAWAN_1_0_3,
			RegParamsRevision: common.RegParamsRevision_B,
			SupportsOtaa:      true,
			Region:            common.Region_EU868,
			AdrAlgorithmId:    "default",
		},
	})
	var dpID string
	if err == nil {
		dpID = dpResp.Id
	}

	// 3. Application
	appName, _ := uuid.NewV4()
	appResp, err := appClient.Create(ctx, &api.CreateApplicationRequest{
		Application: &api.Application{
			Name:        "app-" + appName.String(),
			Description: "Simulation App",
			TenantId:    tenantID,
		},
	})
	var appID string
	if err == nil {
		appID = appResp.Id
	}

	// 4. Device & Keys
	if dpID != "" && appID != "" {
		_, _ = devClient.Create(ctx, &api.CreateDeviceRequest{
			Device: &api.Device{
				DevEui:          devEUI.String(),
				Name:            "dev-" + devEUI.String(),
				Description:     "Simulated Target Device",
				ApplicationId:   appID,
				DeviceProfileId: dpID,
			},
		})

		_, _ = devClient.CreateKeys(ctx, &api.CreateDeviceKeysRequest{
			DeviceKeys: &api.DeviceKeys{
				DevEui: devEUI.String(),
				NwkKey: appKey.String(), // In LoRaWAN 1.0.x NwkKey = AppKey
			},
		})
	}

	return nil
}
