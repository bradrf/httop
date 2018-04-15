HTTP top: report statistics about HTTP connections within TCP connections (pcap)

httop => conn-tracker => http-conn => http-stream(client & server) => create-stats

-+- httop: packet ingestion manager
 |
 +-+- connection tracker: manages tcp connections processing http request/responses
   |
   +-+- http connection: manages one set of server and client http streams
     |
     +--- http stream: manages either a client or a sever http stream

http streams share...
  * a queue of request sent times (to track elapsed time to respond)
  * http statistics
