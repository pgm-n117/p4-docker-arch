/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * This file has been modified. 
 * Modifications Copyright © 2021 Saab AB / Mandar Joshi
 * Modifications Copyright © 2025 Pablo Gomariz
 */

/*
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


/* -*- P4_16 -*- */



#include <core.p4>
//#include <tna.p4>
#include <v1model.p4>

#include "int/headers.p4"
#include "int/bmv2_parsers.p4"
//#include "int/sink.p4"
//#include "int/transit.p4"
//#include "int/source.p4"


#include "int/port_counters.p4"
#include "int/port_meters.p4"
#include "int/packet_io.p4"
#include "int/bmv2_forward.p4"
#include "int/checksums.p4"

/*************************************************************************
****************  I N G R E S S   P R O C E S S I N G   ******************
*************************************************************************/
//TODO: ADAPT INGRESS AND EGRESS TO BMV2 V1MODEL FORMAT.

/* Ingress parameters:
*   headers_t: struct defining the headers
*   local_metadata_t: struct defining local metadata
*   standard_metadata_t: standard metadata from v1model
*/

control MyIngress(inout headers hdr,
                inout local_metadata_t meta,
                inout standard_metadata_t standard_metadata){

    apply{
        //port counters
        port_counters_ingress.apply(hdr, standard_metadata);
        //ingress meter

        port_meters_ingress.apply(hdr, standard_metadata);
        //packetio: TODO: understand this procedure
        packetio_ingress.apply(hdr, standard_metadata);
        //forwarding table
        table0_portforward_control.apply(hdr, meta, standard_metadata);
        //int processing (source or sink)
        //process_int_source_sink.apply(hdr, meta, standard_metadata); //source.p4


        //if int source, apply source processing

        //if int sink, clone packet for telemetry report
    }
                
}

#ifdef __TOFINO__
control MyIngress(inout headers hdr,
                  inout local_metadata_t local_metadata,
                  in ingress_intrinsic_metadata_t ig_intr_md,
                  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    

    apply {

        port_forward.apply(hdr, local_metadata, ig_tm_md, ig_dprsr_md);
        
        process_int_source_sink.apply(hdr, local_metadata, ig_intr_md, ig_tm_md);

        if (local_metadata.int_meta.source == _TRUE) {
            process_int_source.apply(hdr, local_metadata);
        }

        if (local_metadata.int_meta.sink == _TRUE && hdr.int_header.isValid()) {
            // clone packet for Telemetry Report
            //TODO: IMPLEMENT CLONE MAYBE TO CONTROLLER, OR TO INDICATED PORT
            //https://github.com/p4lang/p4c/blob/cc6359735443be2abd9c0a7a947e7c7ad72d1a2e/p4include/v1model.p4#L640
            ig_dprsr_md.mirror_type = MIRROR_TYPE_I2E;
            local_metadata.pkt_type = PKT_TYPE_MIRROR; 
            local_metadata.ing_mir_ses = (bit<10>) MIRROR_TYPE_I2E;
        }

        if (hdr.int_header.isValid()) {
            // Save ingress parser values for egress / INT Transit
            hdr.local_report_header.setValid();
            hdr.local_report_header.ingress_port_id = (bit<16>) ig_intr_md.ingress_port;
            hdr.local_report_header.queue_id = (bit<8>) ig_tm_md.qid;
            hdr.local_report_header.ingress_global_tstamp = (bit<64>) ig_intr_md.ingress_mac_tstamp;
        }
    }
}
#endif

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                inout local_metadata_t meta,
                inout standard_metadata_t standard_metadata){

    apply{
        //TODO: Implement when INT is ready
        //if(hdr.int_header.isValid()) {
        //}

        //port counters
        port_counters_egress.apply(hdr, standard_metadata);
        //egress meter
        port_meters_egress.apply(hdr, standard_metadata);
        //packetio: TODO: understand this procedure
        packetio_egress.apply(hdr, standard_metadata);
    }


}

#ifdef __TOFINO__
control MyEgress(inout headers hdr,
                 inout local_metadata_t local_metadata,
                 in egress_intrinsic_metadata_t eg_intr_md,
                 in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
                 inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
                 inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    
    apply {
        if(hdr.int_header.isValid()) {

            process_set_sink.apply(hdr, local_metadata, eg_intr_md);

            if (local_metadata.int_meta.sink == _TRUE) {
                process_int_sink.apply(hdr, local_metadata);
                
            } else if (local_metadata.int_meta.sink == _FALSE) {
                if(hdr.mirror_header.isValid()) {
                //TODO: IMPLEMENT CLONE MAYBE TO CONTROLLER, OR TO INDICATED PORT
                    hdr.local_report_header.ingress_port_id = hdr.mirror_header.ingress_port_id;
                    hdr.local_report_header.queue_id = hdr.mirror_header.queue_id;
                    hdr.local_report_header.ingress_global_tstamp = hdr.mirror_header.ingress_global_tstamp;
                }
                process_int_transit.apply(hdr, local_metadata, eg_intr_md, eg_prsr_md);
            }
            
            if (local_metadata.mirror == _TRUE) {       // Packet is a mirror
            //TODO: IMPLEMENT CLONE MAYBE TO CONTROLLER, OR TO INDICATED PORT
                process_int_report.apply(hdr, local_metadata, eg_intr_md, eg_prsr_md);
            }
        }

        hdr.local_report_header.setInvalid();
        //TODO: IMPLEMENT CLONE MAYBE TO CONTROLLER, OR TO INDICATED PORT
        hdr.mirror_header.setInvalid();
    }
}
#endif
/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
        MyIngressParser(),
        verify_checksum_control(),
        MyIngress(),
        MyEgress(),
        compute_checksum_control(),
        MyEgressDeparser()
    ) main;

