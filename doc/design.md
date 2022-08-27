# `magna` Design
Author: robjs@google.com
Last Updated: 2022-08-09

`magna` is a modular implementation of an automated test equipment (ATE) device
that implements the [Open Traffic
Generator](https://github.com/open-traffic-generator/models) control API and
gNMI telemetry.

`magna` is designed to be modular, such that it can be easily extended for new
use cases. The base implementation does not cover all the OTG APIs, or
functionality. More complete implementations such as `ixia-c` are likely to be
more suited to ongoing testing, an implementation like `magna` allows
additional flexibility to cover features not yet supported in these
implementations, or to test independently of a third-party implementation.

## Modules

`magna` consists of a number of modules:

 * `lwotg` - which defines a server that exposes the [OTG gRPC
   service](https://github.com/open-traffic-generator/models/blob/master/artifacts/otg.proto#L13959-L13992).
`lwotg` acts as a caller for other methods that enable:
   * translation of an OTG configuration to some action on a device - e.g.,
     configuring IP addresses on interfaces.
   * parsing flow information and providing traffic generator functions
   * communicating configuration information to other components of the system
     that subsequently need them to 
 * `lwotgtelem` that exposes a gNMI server returning telemetry corresponding to
   the [OTG YANG
models](https://github.com/open-traffic-generator/models-yang).
   * As with the configuration, `lwotgtelem` is a pluggable design - using the
     same approach as [lemming's](https://github.com/openconfig/lemming)
`gnmit`. Individual "tasks" are created which report specific telemetry.
   * Since the OTG YANG models require some knowledge of the configuration
     (e.g., mapping to user-specified interface names) `lwotg` publishes a set
of `<key, value>` hints that are used by `lwotg` telemetry to create telemetry
updates.
 * `intf` - a library that provides low-level access to configuring an
   underlying system. Initial implementation is provided for Linux, but it is
envisaged that the same underlying functionality can be implemented for
gRPC-based wires.
 * `flows` - a library that provides functions that map between a set of flows
   defined in OTG, and a set of functions that generate and receive those
flows. "Handler" functions can be registered with `lwotg` that map specific
flows - such that users can add new types of flows that are not currently
supported.
   * The initial implementation of `flows` generates packets via `gopacket` and
     uses `pcap` to write those packets to underlying interfaces, functions
that perform the same handling and write to gRPC wires are also possible.

The `magna` binary itself insantiates a `lwotg` and `lwotgtelem` server, and
registers the relevant telemetry, protocol start/stop, and flow handlers
against it. It can be built and run in a container for use within
[`kne`](https://github.com/openconfig/kne) topologies, and similar places where
traffic generation is required.

`magna` does not currently support:

 * Any emulated protocol, it does the minimum possible to support IP
   connectivity between `magna` and the other side of a link.
 * Actions other than starting and stopping protocols and traffic.

## High-Level `magna` Flow

A typical test case consists of configuring the ATE, starting protocols on it
to establish connectivity with a DUT, starting and stopping a traffic flow, and
reading statistics via telemetry.

`magna` supports this flow by:

 * At server start time spawning the gRPC server that supports the gNMI
   interface, and any registered telemetry `Task` methods. These tasks take
some data source and publish it to gNMI when required.
    * Tasks such as reporting ARP entries, and physical interfaces can be
      supported by this mechanism.
 * An external client (typically a test) sets an OTG configuration via the OTG
   `SetConfig` RPC:
    * `lwotg` calls each registered configuration handler function is called by
      `lwotg` to realise this configuration on the underlying host.
    * `lwotg` also calls each registered flow handler function to pre-stage the
      methods that will enable traffic generation for the configuration. These
flow handler functions return functions which are subsequently called when
traffic is started, and communicated with via a set of Go channels.
 * The external client calls the `SetProtocolState` RPC which calls a
   registered handler function to ensure that any pre-requisites to sending
traffic are performed. This may include sending ARP requests, gARP responses,
or ICMP reachability checks.
 * The external client calls the `SetTransmitState` to start traffic, `lwotg`
   calls the registred flow handler functions to start flows. They are
cancelled when the client again calls `SetTransmitState` to stop the flows.
   * Flow handler functions return the telemetry that they have related to the
     flows that they are suitable to handle. This allows Tx and Rx stats to be
     returned throughout the flows.
