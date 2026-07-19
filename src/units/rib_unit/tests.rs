use crate::common::status_reporter::AnyStatusReporter;
use crate::roto_runtime::types::{
    explode_announcements, explode_withdrawals,
};
use crate::tests::util::internal::get_testable_metrics_snapshot;
use crate::{
    bgp::encode::{mk_bgp_update, Announcements, Prefixes},
    payload::{Payload, Update},
    units::rib_unit::unit::RibUnitRunner,
};
use chrono::Utc;
use futures::future::join_all;
use inetnum::{addr::Prefix, asn::Asn};
use rotonda_store::{
    epoch,
    match_options::{IncludeHistory, MatchOptions, MatchType},
    prefix_record::RouteStatus,
};
use routecore::bgp::communities::Wellknown;
use routecore::bgp::message::update_builder::StandardCommunitiesList;
use routecore::bgp::message::{SessionConfig, UpdateMessage};
use routecore::bgp::path_attributes::{PathAttribute, PathAttributeType};
use routecore::bgp::types::AfiSafiType;
use smallvec::SmallVec;

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::atomic::Ordering::SeqCst;
use std::time::Duration;
use std::{str::FromStr, sync::Arc};

use super::status_reporter::RibUnitStatusReporter;

const MRTGEN_E2E_ROUTES: &str = r#"[
    {
        "prefix": "192.0.2.0/24",
        "nexthop": "198.51.100.1",
        "as_path": [64500, 64496],
        "origin": "incomplete",
        "med": 50,
        "local_pref": 150,
        "atomic_aggregate": true,
        "aggregator": "4200000001:203.0.113.9",
        "originator_id": "198.51.100.9",
        "cluster_list": ["198.51.100.10", "198.51.100.11"],
        "standard_communities": ["64500:100", "no-export"],
        "extended_communities": ["rt:64500:200", "soo:4200000001:300"],
        "large_communities": ["64500:400:500"]
    },
    {
        "prefix": "2001:db8:100::/48",
        "nexthop": "2001:db8::1",
        "as_path": [64501, 4200000001],
        "origin": "egp",
        "med": 75,
        "local_pref": 200,
        "ipv6_extended_communities": ["rt:2001:db8::5:600"],
        "large_communities": ["4200000001:700:800"]
    },
    {
        "prefix": "203.0.113.7/32",
        "nexthop": "198.51.100.2",
        "as_path": []
    },
    {
        "prefix": "2001:db8::7/128",
        "nexthop": "2001:db8::2",
        "as_path": []
    }
]"#;

/// Diverse FlowSpec rules (RFC 8955/8956) covering every component type,
/// both address families, rules with and without a destination prefix, and
/// every traffic action mrtgen can encode. The unicast route comes first so
/// the 192.0.2.0/24 rule validates against it (same peer, RFC 8955 §6).
const MRTGEN_FLOWSPEC_ROUTES: &str = r#"[
    {
        "prefix": "192.0.2.0/24",
        "nexthop": "198.51.100.1",
        "as_path": [64500]
    },
    {
        "flowspec": {
            "dst_prefix": "192.0.2.0/24",
            "protocol": [6],
            "dst_port": [80, 443]
        },
        "actions": { "rate_limit_bytes": 0 }
    },
    {
        "flowspec": {
            "dst_prefix": "198.51.100.0/24",
            "protocol": [6],
            "tcp_flags": [{"flags": ["syn"], "match": true}],
            "packet_length": [{"range": [512, 1500]}]
        },
        "actions": { "redirect": "65100:999", "sample": true }
    },
    {
        "flowspec": {
            "dst_prefix": "198.51.100.0/24",
            "protocol": [1],
            "icmp_type": [8],
            "icmp_code": [0],
            "dscp": [46],
            "fragment": [{"flags": ["is-fragment"]}]
        },
        "actions": { "traffic_marking": 22, "terminal_action": true }
    },
    {
        "flowspec": {
            "src_prefix": "203.0.113.0/24",
            "protocol": [17],
            "src_port": [{"range": [1024, 65535]}]
        },
        "actions": { "redirect": "198.51.100.9:100" }
    },
    {
        "flowspec": {
            "dst_prefix": "2001:db8:1::/48",
            "protocol": [6],
            "dst_port": [443]
        },
        "actions": { "rate_limit_bytes": 1000000.0 }
    },
    {
        "flowspec": {
            "src_prefix": "2001:db8:2::/48",
            "flow_label": [{"gt": 0}]
        },
        "actions": { "rate_limit_bytes": 0 }
    }
]"#;

async fn ingest_mrtgen_routes(
    format: mrtgen::RouteFormat,
    extension: &str,
) -> Arc<RibUnitRunner> {
    ingest_mrtgen_routes_json(MRTGEN_E2E_ROUTES, format, extension).await
}

async fn ingest_mrtgen_routes_json(
    routes_json: &str,
    format: mrtgen::RouteFormat,
    extension: &str,
) -> Arc<RibUnitRunner> {
    use crate::comms::{DirectLink, Gate};
    use crate::ingress;
    use crate::units::mrt_file_in::unit::MrtInRunner;
    use mrtgen::{generate_from_routes, routes_from_json};
    use std::io::Write;

    // Every call gets a distinct file: the tests share one process, and
    // e.g. the TableDumpV2 and BGP4MP tests over the same corpus run in
    // parallel — any name derived from (pid, corpus, extension) alone
    // collides and one test deletes the file under the other.
    static TMP_SEQ: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    let routes = routes_from_json(routes_json).unwrap();
    let corpus =
        generate_from_routes(&routes, format, 1_700_000_000).unwrap();
    let path = std::env::temp_dir().join(format!(
        "netom-mrtgen-e2e-{}-{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, SeqCst),
        extension
    ));
    match extension {
        "mrt" => std::fs::write(&path, &corpus.bytes).unwrap(),
        "gz" => {
            let file = std::fs::File::create(&path).unwrap();
            let mut encoder = flate2::write::GzEncoder::new(
                file,
                flate2::Compression::default(),
            );
            encoder.write_all(&corpus.bytes).unwrap();
            encoder.finish().unwrap();
        }
        "bz2" => {
            let file = std::fs::File::create(&path).unwrap();
            let mut encoder = bzip2::write::BzEncoder::new(
                file,
                bzip2::Compression::default(),
            );
            encoder.write_all(&corpus.bytes).unwrap();
            encoder.finish().unwrap();
        }
        _ => unreachable!(),
    }

    let (mrt_gate, mut mrt_gate_agent) = Gate::new(0);
    let update_gate = mrt_gate.clone();
    let gate_task =
        tokio::spawn(
            async move { while mrt_gate.process().await.is_ok() {} },
        );

    let (rib_runner, _rib_gate_agent) = RibUnitRunner::mock("").unwrap();
    let rib_runner = Arc::new(rib_runner);
    let mut link: DirectLink = mrt_gate_agent.create_link().into();
    link.connect(rib_runner.clone(), false).await.unwrap();

    let ingresses = Arc::new(ingress::Register::new());
    let parent_id = ingresses.register();
    let result = MrtInRunner::process_file(
        update_gate,
        ingresses,
        parent_id,
        path.clone(),
    )
    .await;
    let _ = std::fs::remove_file(path);
    gate_task.abort();

    result.expect("MRT input should reach the RIB through the gate");
    rib_runner
}

fn assert_e2e_prefixes(runner: &RibUnitRunner) {
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        4
    );
    let options = MatchOptions {
        match_type: MatchType::ExactMatch,
        include_withdrawn: false,
        include_less_specifics: false,
        include_more_specifics: false,
        mui: None,
        include_history: IncludeHistory::None,
    };
    for prefix in [
        "192.0.2.0/24",
        "2001:db8:100::/48",
        "203.0.113.7/32",
        "2001:db8::7/128",
    ] {
        let prefix = Prefix::from_str(prefix).unwrap();
        let result = runner.rib().match_prefix(&prefix, &options).unwrap();
        assert_eq!(result.records.len(), 1, "missing {prefix} from RIB");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ingests_mrtgen_attributes_into_rib_and_json() {
    use crate::representation::Json;
    use crate::units::rib_unit::http_ng::QueryFilter;
    use routecore::bgp::path_attributes::{
        AggregatorInfo, ClusterIds, ExtendedCommunitiesList,
        LargeCommunitiesList,
    };
    use routecore::bgp::types::{
        AtomicAggregate, LocalPref, MultiExitDisc, OriginatorId,
    };

    let runner =
        ingest_mrtgen_routes(mrtgen::RouteFormat::TableDumpV2, "mrt").await;
    assert_e2e_prefixes(&runner);

    let prefix = Prefix::from_str("192.0.2.0/24").unwrap();
    let record = stored_record(&runner, &prefix);
    let attrs = record.meta.path_attributes();
    assert_eq!(attrs.get::<MultiExitDisc>().unwrap().0, 50);
    assert_eq!(attrs.get::<LocalPref>().unwrap().0, 150);
    assert!(attrs.get::<AtomicAggregate>().is_some());
    assert_eq!(
        attrs.get::<AggregatorInfo>().unwrap().asn().into_u32(),
        4_200_000_001
    );
    assert_eq!(
        attrs.get::<OriginatorId>().unwrap().0.to_string(),
        "198.51.100.9"
    );
    assert_eq!(attrs.get::<ClusterIds>().unwrap().len(), 2);
    assert_eq!(
        attrs
            .get::<StandardCommunitiesList>()
            .unwrap()
            .communities()
            .len(),
        2
    );
    assert_eq!(
        attrs
            .get::<ExtendedCommunitiesList>()
            .unwrap()
            .communities()
            .len(),
        2
    );
    assert_eq!(
        attrs
            .get::<LargeCommunitiesList>()
            .unwrap()
            .communities()
            .len(),
        1
    );

    let mut json = Vec::new();
    runner
        .rib()
        .search_and_output_routes(
            Json(&mut json),
            AfiSafiType::Ipv4Unicast,
            prefix,
            QueryFilter::default(),
        )
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(json["data"]["nlri"], "192.0.2.0/24");
    assert_eq!(json["data"]["routes"][0]["status"], "active");
    assert!(json["data"]["routes"][0]["pathAttributes"].is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn ingests_mrtgen_bgp4mp_updates() {
    let runner =
        ingest_mrtgen_routes(mrtgen::RouteFormat::Bgp4mp, "mrt").await;
    assert_e2e_prefixes(&runner);
}

/// End-to-end FlowSpec via MRT: a mrtgen-generated BGP4MP file with diverse
/// SAFI 133 rules must land in the flowspec store with correct keying
/// (dst-prefix, or the family default route without one), RFC 8955 §6
/// validity, decodable NLRI bytes and decodable traffic actions.
#[tokio::test(flavor = "multi_thread")]
async fn ingests_mrtgen_flowspec_rules() {
    use super::flowspec::{decode_actions, parse_raw_nlri, FlowSpecValidity};

    let runner = ingest_mrtgen_routes_json(
        MRTGEN_FLOWSPEC_ROUTES,
        mrtgen::RouteFormat::Bgp4mp,
        "mrt",
    )
    .await;

    // The plain unicast route travelled alongside the flowspec rules.
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    let v4 = runner
        .rib()
        .query_flowspec(true, None, false, false, None, None)
        .unwrap();
    let v6 = runner
        .rib()
        .query_flowspec(false, None, false, false, None, None)
        .unwrap();
    assert_eq!(v4.len(), 4, "expected 4 stored IPv4 flowspec rules");
    assert_eq!(v6.len(), 2, "expected 2 stored IPv6 flowspec rules");

    // Every stored rule must parse back from its raw NLRI bytes and carry
    // decodable traffic actions (each corpus rule has at least one).
    for (rows, family_v4) in [(&v4, true), (&v6, false)] {
        for row in rows.iter() {
            let nlri = parse_raw_nlri(&row.rule.nlri, family_v4)
                .unwrap_or_else(|| {
                    panic!("undecodable NLRI at {}", row.key_prefix)
                });
            assert!(
                !decode_actions(&row.rule.pamap).is_empty(),
                "no decoded actions for {nlri} at {}",
                row.key_prefix
            );
        }
    }

    // Keying: one rule per dst-prefix, two sharing 198.51.100.0/24, and the
    // dst-less rules at their family default route.
    let key_count = |rows: &[_], key: &str| {
        rows.iter()
            .filter(|r: &&super::flowspec::FlowSpecQueryRow| {
                r.key_prefix.to_string() == key
            })
            .count()
    };
    assert_eq!(key_count(&v4, "192.0.2.0/24"), 1);
    assert_eq!(key_count(&v4, "198.51.100.0/24"), 2);
    assert_eq!(key_count(&v4, "0.0.0.0/0"), 1);
    assert_eq!(key_count(&v6, "2001:db8:1::/48"), 1);
    assert_eq!(key_count(&v6, "::/0"), 1);

    // RFC 8955 §6 validity: the 192.0.2.0/24 rule is covered by the unicast
    // route from the same peer (ingested first) -> Valid; the other keyed
    // rules have no covering unicast route -> Invalid; dst-less rules are
    // Unvalidatable.
    for row in v4.iter().chain(v6.iter()) {
        let expected = match row.key_prefix.to_string().as_str() {
            "192.0.2.0/24" => FlowSpecValidity::Valid,
            "198.51.100.0/24" | "2001:db8:1::/48" => {
                FlowSpecValidity::Invalid
            }
            _ => FlowSpecValidity::Unvalidatable,
        };
        assert_eq!(
            row.rule.validity, expected,
            "validity mismatch at {}",
            row.key_prefix
        );
    }
}

/// RFC 8955 §6 validation must treat routes stored under ADD-PATH
/// path-child muis (`IngressType::BgpPath`) as coming from the same peer as
/// their parent session: the child register entries carry no bgp_id of
/// their own, so without resolving children to their session a flowspec
/// rule under a child mui and its covering unicast route under the session
/// mui compare as different originators and the rule is falsely Invalid.
#[tokio::test(flavor = "multi_thread")]
async fn flowspec_validation_spans_addpath_child_muis() {
    use super::flowspec::FlowSpecValidity;
    use crate::ingress::{IngressInfo, IngressType};
    use crate::payload::RotondaRoute;

    let (runner, _agent) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();
    let register = rib.ingress_register.clone();

    let session = register.register();
    register.update_info(
        session,
        IngressInfo::new()
            .with_ingress_type(IngressType::Bmp)
            .with_remote_addr(IpAddr::from_str("10.0.0.1").unwrap())
            .with_remote_asn(Asn::from_u32(64500))
            .with_bgp_id([192, 0, 2, 1]),
    );
    // A path child the way the mint sites created them before bgp_id was
    // added there: display fields only.
    let child = register.register();
    register.update_info(
        child,
        IngressInfo::new()
            .with_ingress_type(IngressType::BgpPath)
            .with_parent_ingress(session)
            .with_path_id(1u32)
            .with_remote_addr(IpAddr::from_str("10.0.0.1").unwrap())
            .with_remote_asn(Asn::from_u32(64500)),
    );

    // Covering unicast route under the SESSION mui.
    let ann =
        Announcements::from_str("e [64500] 10.0.0.1 none 192.0.2.0/24")
            .unwrap();
    let bgp_update_bytes = mk_bgp_update(&Prefixes::default(), &ann, &[]);
    let update_msg = UpdateMessage::from_octets(
        bgp_update_bytes,
        &SessionConfig::modern(),
    )
    .unwrap();
    let (unicast, _) =
        explode_announcements(&update_msg).unwrap().pop().unwrap();
    let pamap = match &unicast {
        RotondaRoute::Ipv4Unicast(_, pamap) => pamap.clone(),
        other => panic!("unexpected route {other:?}"),
    };
    rib.insert(&unicast, RouteStatus::Active, 1, session, true, false)
        .unwrap();

    // FlowSpec rule "dst 192.0.2.0/24" under the CHILD mui, carrying the
    // same path attributes (notably: no ORIGINATOR_ID, so identity falls
    // back to the register's bgp_id).
    let raw_nlri = [0x01u8, 24, 192, 0, 2];
    let nlri = super::flowspec::parse_raw_nlri(&raw_nlri, true).unwrap();
    let rr = RotondaRoute::Ipv4FlowSpec(nlri.into(), pamap);
    rib.insert(&rr, RouteStatus::Active, 2, child, true, false)
        .unwrap();

    let rows = rib
        .query_flowspec(true, None, false, false, None, None)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].rule.validity,
        FlowSpecValidity::Valid,
        "flowspec rule under a path-child mui must validate against the \
         session's unicast route"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unicast_api_exposes_addpath_session_path_and_internal_child() {
    use crate::ingress::{IngressInfo, IngressType};
    use crate::payload::{RotondaPaMap, RotondaRoute};

    let (runner, _agent) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();
    let register = rib.ingress_register.clone();

    let session = register.register();
    register.update_info(
        session,
        IngressInfo::new().with_ingress_type(IngressType::Bgp),
    );
    let child = register.register();
    register.update_info(
        child,
        IngressInfo::new()
            .with_ingress_type(IngressType::BgpPath)
            .with_parent_ingress(session)
            .with_path_id(77u32),
    );

    let prefix = inetnum::addr::Prefix::from_str("198.51.100.0/24").unwrap();
    let route = RotondaRoute::Ipv4Unicast(
        prefix.try_into().unwrap(),
        RotondaPaMap::empty_path_attributes(),
    );
    rib.insert(&route, RouteStatus::Active, 1, child, true, false)
        .unwrap();

    let mut json = Vec::new();
    rib.search_and_output_routes(
        crate::representation::Json(&mut json),
        AfiSafiType::Ipv4Unicast,
        prefix,
        super::QueryFilter::default(),
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&json).unwrap();
    let row = &json["data"]["routes"][0];
    assert_eq!(row["ingress"]["id"], child);
    assert_eq!(row["source"]["ingressId"], session);
    assert_eq!(row["source"]["pathId"], 77);
    assert_eq!(row["source"]["internalPathIngressId"], child);
}

#[tokio::test(flavor = "multi_thread")]
async fn ingests_compressed_mrtgen_files() {
    for extension in ["gz", "bz2"] {
        let runner =
            ingest_mrtgen_routes(mrtgen::RouteFormat::TableDumpV2, extension)
                .await;
        assert_e2e_prefixes(&runner);
    }
}

#[ignore]
#[tokio::test]
async fn process_non_route_update() {
    /*
    let (runner, _) = RibUnitRunner::mock(
        "",
        RibType::Physical,
    );

    // Given an update that is not a route
    let update = Update::from(Payload::from(TypeValue::Unknown));

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update).await);

    // And it should NOT be added to the route store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 0);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (0, 0, 0, 0, 0));
    */
}

#[tokio::test]
async fn process_update_single_route() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update).await);
    runner.process_update(update).await.unwrap();

    // And it should be added to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));
}

#[tokio::test]
#[ignore = "this is really different after refactoring of the store"]
async fn process_update_withdraw_unannounced_route() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();

    // Given a BGP update containing a single route withdrawal
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, None);

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update.clone()).await);
    runner.process_update(update.clone()).await.unwrap();

    // And it should cause the prefix to be added to the route store
    // LH: errr, it should not?
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        0
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (0, 1, 0, 0, 1));

    //// When it is processed again by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update).await);
    runner.process_update(update).await.unwrap();

    // And it should cause the prefix to be added to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (0, 2, 0, 0, 1));
}

#[tokio::test]
async fn process_update_same_route_twice() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update.clone()).await);
    runner.process_update(update.clone()).await.unwrap();

    // And it should be added to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    //// When it is processed by this unit again it should not be filtered
    //assert!(!is_filtered(&runner, update).await);
    runner.process_update(update.clone()).await.unwrap();

    // And it should NOT be added again to the route store
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));

    // But when withdrawn
    let update = mk_route_update(&prefix, None);

    //// When it is processed by this unit it should not be filtered
    //assert!(!is_filtered(&runner, update.clone()).await);
    runner.process_update(update).await.unwrap();

    // And it should cause the route to be marked as withdrawn
    assert_eq!(
        runner.rib().store().unwrap().prefixes_count().in_memory(),
        1
    );

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 0, 1, 1));
}

#[tokio::test]
async fn process_update_withdraw_retains_attributes_by_default() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix, Some("[111,222,333]")))
        .await
        .unwrap();
    let announced_attr_len = stored_attr_len(&runner, &prefix);
    assert!(announced_attr_len > 2);

    runner
        .process_update(mk_route_update(&prefix, None))
        .await
        .unwrap();

    assert_eq!(stored_status(&runner, &prefix), RouteStatus::Withdrawn);
    assert_eq!(stored_attr_len(&runner, &prefix), announced_attr_len);
}

#[tokio::test]
async fn process_update_withdraw_can_drop_attributes() {
    let (runner, _) =
        RibUnitRunner::mock_with_retain_withdrawn_attributes(false).unwrap();
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix, Some("[111,222,333]")))
        .await
        .unwrap();
    assert!(stored_attr_len(&runner, &prefix) > 2);

    runner
        .process_update(mk_route_update(&prefix, None))
        .await
        .unwrap();

    assert_eq!(stored_status(&runner, &prefix), RouteStatus::Withdrawn);
    assert_eq!(stored_attr_len(&runner, &prefix), 2);
}

#[tokio::test]
async fn process_peer_withdraw_can_drop_attributes() {
    let (runner, _) =
        RibUnitRunner::mock_with_retain_withdrawn_attributes(false).unwrap();
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix, Some("[111,222,333]")))
        .await
        .unwrap();
    assert!(stored_attr_len(&runner, &prefix) > 2);

    runner
        .process_update(Update::Withdraw(1, None))
        .await
        .unwrap();

    assert_eq!(stored_status(&runner, &prefix), RouteStatus::Withdrawn);
    assert_eq!(stored_attr_len(&runner, &prefix), 2);
}

#[tokio::test]
async fn process_update_can_deduplicate_path_attributes() {
    let (runner, _) =
        RibUnitRunner::mock_with_deduplicate_path_attributes(true).unwrap();
    let prefix_one = Prefix::from_str("127.0.0.1/32").unwrap();
    let prefix_two = Prefix::from_str("127.0.0.2/32").unwrap();

    runner
        .process_update(mk_route_update(&prefix_one, Some("[111,222,333]")))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update(&prefix_two, Some("[111,222,333]")))
        .await
        .unwrap();

    let record_one = stored_record(&runner, &prefix_one);
    let record_two = stored_record(&runner, &prefix_two);

    assert_eq!(record_one.meta.as_ref(), record_two.meta.as_ref());
    assert_eq!(
        record_one.meta.as_ref().as_ptr(),
        record_two.meta.as_ref().as_ptr()
    );
}

#[ignore]
#[tokio::test]
async fn process_update_equivalent_route_twice() {
    /*
    let (runner, _) = RibUnitRunner::mock("");

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update_with_communities(
        &prefix,
        Some("[111,222,333]"),
        Some("BLACKHOLE"),
    );

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update.clone()).await);

    // And it should be added to the route store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    assert_eq!(
        metrics
            .with_name::<usize>("rib_unit_num_modified_route_announcements"),
        0
    );

    // And check the value stored
    let match_options = MatchOptions {
        match_type: MatchType::ExactMatch,
        include_withdrawn: false,
        mui: None,
        include_less_specifics: true,
        include_more_specifics: true,
    };
    eprintln!("Querying store match_prefix the first time");
    let match_result = runner.rib().store().unwrap().match_prefix(
        &prefix,
        &match_options,
        &epoch::pin(),
    );
    assert!(matches!(match_result.match_type, MatchType::ExactMatch));
    let rib_value = match_result.prefix_meta;
    assert_eq!(rib_value.len(), 1);
    let pubrecord = rib_value.iter().next().unwrap();
    let route = *pubrecord.meta;
    if let Some(comms) = route.get_attr::<StandardCommunitiesList>() {
        assert_eq!(
            comms.communities()
                .first()
                .unwrap(),
            Wellknown::Blackhole.into()
        );
    } else {
        unreachable!()
    };

    // When a route that is identical by key but different by value then the
    // new route should not be filtered, where the default key is peer IP,
    // peer ASN and AS path (see RibUnit::default_rib_keys()).
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update_with_communities(
        &prefix,
        Some("[111,222,333]"),
        Some("NO_EXPORT"),
    );
    if let Update::Single(Payload {
        rx_value: TypeValue::Builtin(BuiltinTypeValue::PrefixRoute(route)),
        ..
    }) = &update
    {
        assert_eq!(
            route
                .raw_message
                .0
                .communities()
                .unwrap()
                .unwrap()
                .next()
                .unwrap(),
            Wellknown::NoExport.into()
        );
    }
    assert!(!is_filtered(&runner, update).await);

    // And should replace the old route in the store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);
    let match_options = MatchOptions {
        match_type: MatchType::ExactMatch,
        include_all_records: true,
        include_less_specifics: true,
        include_more_specifics: true,
    };
    eprintln!("Querying store match_prefix the second time");
    let match_result = runner.rib().store().unwrap().match_prefix(
        &prefix,
        &match_options,
        &epoch::pin(),
    );
    assert!(matches!(match_result.match_type, MatchType::ExactMatch));
    let rib_value = match_result.prefix_meta.as_ref().unwrap();
    assert_eq!(rib_value.len(), 1);
    let prehashed_type_value = rib_value.iter().next().unwrap();
    if let TypeValue::Builtin(BuiltinTypeValue::Route(route)) =
        &***prehashed_type_value
    {
        assert_eq!(
            route
                .raw_message
                .0
                .communities()
                .unwrap()
                .unwrap()
                .next()
                .unwrap(),
            Wellknown::NoExport.into()
        );
    } else {
        unreachable!()
    };

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 1, 0, 1));

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    assert_eq!(
        metrics
            .with_name::<usize>("rib_unit_num_modified_route_announcements"),
        1
    );

    // But when withdrawn
    let update = mk_route_update(&prefix, None);

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update.clone()).await);

    // And it should cause the route to be marked as withdrawn
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (1, 0, 0, 1, 1));
    */
}

#[ignore]
#[tokio::test]
async fn process_update_two_routes_to_the_same_prefix() {
    /*
    #[rustfmt::skip]
    let (_match_result, match_result2) = {
        let (runner, _) = RibUnitRunner::mock("", RibType::Physical);

        // Given BGP updates for two different routes to the same prefix
        let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
        for as_path_str in ["[111,222,333]", "[111,444,333]"] {
            let update = mk_route_update(&prefix, Some(as_path_str));
            assert!(!is_filtered(&runner, update.clone()).await);
        }

        // Then only the one common prefix SHOULD be added to the route store
        assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

        // And check that recorded metrics are correct
        assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 2, 0, 1));

        // And at that prefix there should be one RibValue containing two routes
        let match_options = MatchOptions {
            match_type: MatchType::ExactMatch,
            include_less_specifics: true,
            include_more_specifics: true,
        };
        eprintln!("Querying store match_prefix the first time");
        let match_result = runner.rib().store().unwrap().match_prefix(
            &prefix,
            &match_options,
            &epoch::pin(),
        );
        assert!(matches!(match_result.match_type, MatchType::ExactMatch));
        let rib_value = match_result.prefix_meta.as_ref().unwrap();
        assert_eq!(rib_value.len(), 2);

        // Check the Arc reference counts. The routes HashSet should have a strong reference count of 2 because the
        // MultiThreadedStore has the original Arc around the metadata that was inserted into the store, and it clones
        // that Arc when making a "copy" to include in the match prefix result set, thereby incrementing the strong
        // reference count. The items in the routes HashSet however should have a strong reference count of 1. This is
        // because we are accessing the one and only copy of the HashSet via the Arc and are thus seeing the actual
        // HashSet copy held by the store and thus its actual items, which have not been cloned and thus have a strong
        // reference count of 1. As we don't at this point use any Weak references to the HashSet or its items the
        // weak reference counts should be 0.
        assert_eq!(Arc::strong_count(rib_value.test_inner()), 2);
        assert_eq!(Arc::weak_count(rib_value.test_inner()), 0);
        for item in rib_value.iter() {
            assert_eq!(Arc::strong_count(item), 1);
            assert_eq!(Arc::weak_count(item), 0);
        }

        // If we repeat the match prefix query while still holding the previous match prefix query results, we should
        // see that the routes HashSet Arc strong reference count increases from 2 to 3 while the inner items of the
        // HashSet still have a strong reference count of 1.
        eprintln!("Querying store match_prefix the second time");
        let match_result2 = runner.rib().store().unwrap().match_prefix(
            &prefix,
            &match_options,
            &epoch::pin(),
        );
        assert!(matches!(match_result2.match_type, MatchType::ExactMatch));
        let rib_value = match_result2.prefix_meta.as_ref().unwrap();
        assert_eq!(rib_value.len(), 2);
        assert_eq!(Arc::strong_count(rib_value.test_inner()), 3);
        assert_eq!(Arc::weak_count(rib_value.test_inner()), 0);
        for item in rib_value.iter() {
            assert_eq!(Arc::strong_count(item), 1);
            assert_eq!(Arc::weak_count(item), 0);
        }

        // And when withdrawn
        let update = mk_route_update(&prefix, None);

        // When it is processed by this unit it should not be filtered
        assert!(!is_filtered(&runner, update.clone()).await);

        // And it should cause the route to be marked as withdrawn
        assert_eq!(runner.rib().store().unwrap().prefixes_count(), 1);

        // And check that recorded metrics are correct
        assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 0, 2, 1));

        (match_result, match_result2)
    };

    // The MultiThreadedStore has been dropped so the HashSet strong reference count should decrease from 3 to 2.
    eprintln!(
        "Checking the reference counts of the `match_result` query result var inner metadata item"
    );
    let rib_value = match_result2.prefix_meta.unwrap();
    // assert_eq!(Arc::strong_count(&rib_value.per_prefix_items), 2); // TODO: MultiThreadedStore doesn't cleanup on drop...
    assert_eq!(Arc::weak_count(rib_value.test_inner()), 0);
    for item in rib_value.iter() {
        assert_eq!(Arc::strong_count(item), 1);
        assert_eq!(Arc::weak_count(item), 0);
    }
    */
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn process_update_two_routes_to_different_prefixes() {
    /*
    let (runner, _) = RibUnitRunner::mock(
        "",
        RibType::Physical,
    );

    // Given BGP updates for two different routes to two different prefixes
    let prefix1 = Prefix::from_str("127.0.0.1/32").unwrap();
    let prefix2 = Prefix::from_str("127.0.0.2/32").unwrap();

    let update = mk_route_update(&prefix1, Some("[111,222,333]"));
    assert!(!is_filtered(&runner, update.clone()).await);

    let update = mk_route_update(&prefix2, Some("[111,444,333]"));
    assert!(!is_filtered(&runner, update.clone()).await);

    // Then two separate prefixes SHOULD be added to the route store
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 2);

    // And at that prefix there should be two RibValues
    let match_options = MatchOptions {
        match_type: MatchType::ExactMatch,
        include_less_specifics: true,
        include_more_specifics: true,
    };

    for prefix in [prefix1, prefix2] {
        let match_result = runner.rib().store().unwrap().match_prefix(
            &prefix,
            &match_options,
            &epoch::pin(),
        );
        assert!(matches!(match_result.match_type, MatchType::ExactMatch));
        let rib_value = match_result.prefix_meta.unwrap(); // TODO: Why do we get the actual value out of the store here and not an Arc?
        assert_eq!(rib_value.len(), 1);
    }

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 2, 0, 2));

    // And when one prefix is withdrawn
    let update = mk_route_update(&prefix1, None);

    // When it is processed by this unit it should not be filtered
    assert!(!is_filtered(&runner, update.clone()).await);

    // And it should cause the route to be marked as withdrawn
    assert_eq!(runner.rib().store().unwrap().prefixes_count(), 2);

    // And check that recorded metrics are correct
    assert_eq!(query_metrics(&runner.status_reporter()), (2, 0, 1, 1, 2));
    */
}

#[ignore]
#[tokio::test]
async fn time_store_op_durations() {
    /*
    const INSERT_DELAY: Duration = Duration::from_secs(2);
    const UPDATE_DELAY: Duration = Duration::from_secs(3);
    let mut settings = StoreMergeUpdateSettings::new(
        StoreEvictionPolicy::UpdateStatusOnWithdraw,
    );
    settings.delay = Some(UPDATE_DELAY);

    let (runner, _) = RibUnitRunner::mock("", RibType::Physical, settings);

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));
    let started_at = Utc::now();

    // Insert it once, MergeUpdate won't be invoked so there should be no
    // delay there, but we deliberately introduce a delay around the store
    // insert call.
    runner
        .process_update(update.clone(), |pfx, meta, store| {
            eprintln!(
                "Sleeping in insert_fn() for {}ms",
                INSERT_DELAY.as_millis()
            );
            std::thread::sleep(INSERT_DELAY);
            store.insert(pfx, meta)
        })
        .await
        .unwrap();

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    let insert_duration_micros =
        metrics.with_name::<u64>("rib_unit_insert_duration");
    let actual_duration = Duration::from_micros(insert_duration_micros);
    assert_eq!(actual_duration.as_secs(), INSERT_DELAY.as_secs());

    let propagation_duration_millis = metrics.with_label::<u64>(
        "rib_unit_e2e_duration",
        ("router", MOCK_ROUTER_ID),
    );
    let actual_duration = Duration::from_millis(propagation_duration_millis);
    assert_eq!(
        actual_duration.as_secs(),
        (Utc::now() - started_at).to_std().unwrap().as_secs()
    );

    // Insert it again, MergeUpdate should be invoked so insertion should be
    // delayed by DELAY as configured above.
    runner
        .process_update(update, |pfx, meta, store| store.insert(pfx, meta))
        .await
        .unwrap();

    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    let update_duration_micros =
        metrics.with_name::<u64>("rib_unit_update_duration");
    let actual_duration = Duration::from_micros(update_duration_micros);
    assert_eq!(actual_duration.as_secs(), UPDATE_DELAY.as_secs());

    let propagation_duration_millis = metrics.with_label::<u64>(
        "rib_unit_e2e_duration",
        ("router", MOCK_ROUTER_ID),
    );
    let actual_duration = Duration::from_millis(propagation_duration_millis);
    assert_eq!(
        actual_duration.as_secs(),
        (Utc::now() - started_at).to_std().unwrap().as_secs()
    );
    */
}

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn count_insert_retries_during_forced_contention() {
    /*
    const DELAY: Duration = Duration::from_millis(10);
    let mut settings = StoreMergeUpdateSettings::new(
        StoreEvictionPolicy::UpdateStatusOnWithdraw,
    );
    settings.delay = Some(DELAY);

    let (runner, _) = RibUnitRunner::mock("", RibType::Physical, settings);
    let runner = Arc::new(runner);

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    // Insert it.
    eprintln!("PERFORMING INITIAL STORE INSERT");
    runner
        .process_update(update.clone(), |pfx, meta, store| {
            store.insert(pfx, meta)
        })
        .await
        .unwrap();

    // Insert it again multiple times in parallel. MergeUpdate should be
    // invoked so insertion should be delayed by DELAY as configured above.
    // This should cause the parallel updates to contend with each other as
    // they each try to insert into the store at the same prefix "bucket"
    // so later inserts that occur during the sleep of the other must wait
    // for the other to stop sleeping and complete. One thing to note is
    // that the sleep is a thread sleep which will block Tokio on that
    // thread but we use #[tokio::test(flavor = "multi_thread")] attribute
    // on this test to use a multi-threaded Tokio so that blocking an
    // individual thread shouldn't block Tokio entirely, especially given
    // its work-stealing ability. Typically with Tokio one is supposed to
    // run blocking activities on a dedicated blocking Tokio thread pool.
    // This isn't done currentlty in Netom because store inserts are
    // intended and expected to be extremely fast, even with contention.
    // The point noted about thread sleep is only relevant to test builds
    // as release builds don't have the thread sleep code in the MergeUpdate
    // impl.
    eprintln!("PERFORMING PARALLEL STORE UPDATES");
    let mut join_handles = vec![];
    for _ in 0..10 {
        let bg_runner = runner.clone();
        let bg_update = update.clone();
        join_handles.push(tokio::task::spawn(async move {
            bg_runner
                .process_update(bg_update, |pfx, meta, store| {
                    store.insert(pfx, meta)
                })
                .await
        }));
    }

    eprintln!(
        "WAITING IN THEREAD {:?} FOR STORE UPDATES TO COMPLETE",
        std::thread::current().id()
    );
    join_all(join_handles).await;

    eprintln!("STORE UPDATES ARE COMPLETE");
    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    let num_retries =
        metrics.with_name::<usize>("rib_unit_num_insert_retries");
    assert!(num_retries > 0);
    */
}

#[ignore]
#[tokio::test]
async fn count_hard_insert_failures() {
    /*
    let settings = StoreEvictionPolicy::UpdateStatusOnWithdraw.into();
    let (runner, _) = RibUnitRunner::mock("", RibType::Physical, settings);

    // Given a BGP update containing a single route announcement
    let prefix = Prefix::from_str("127.0.0.1/32").unwrap();
    let update = mk_route_update(&prefix, Some("[111,222,333]"));

    // Check that the counter is zero to begin with
    let metrics = runner.status_reporter().metrics().unwrap();
    let metrics = get_testable_metrics_snapshot(&metrics);
    assert_eq!(
        metrics.with_name::<u64>("rib_unit_num_insert_hard_failures"),
        0
    );

    // Insert multiple times and check that the counter increases accordingly
    for expected_counter_value in 1..=10 {
        runner
            .process_update(update.clone(), |_, _, _| {
                eprintln!("Deliberately failing to insert into the store");
                Err(PrefixStoreError::StoreNotReadyError)
            })
            .await
            .unwrap();

        let metrics = runner.status_reporter().metrics().unwrap();
        let metrics = get_testable_metrics_snapshot(&metrics);
        assert_eq!(
            metrics.with_name::<u64>("rib_unit_num_insert_hard_failures"),
            expected_counter_value
        );
    }
    */
}

// --- Test helpers ------------------------------------------------------

fn mk_route_update(
    prefix: &Prefix,
    announced_as_path_str: Option<&str>,
) -> Update {
    mk_route_update_with_communities(
        prefix,
        announced_as_path_str,
        Some("BLACKHOLE,123:44"),
    )
}

fn mk_route_update_with_communities(
    prefix: &Prefix,
    announced_as_path_str: Option<&str>,
    communities: Option<&str>,
) -> Update {
    //let _delta_id = (RotondaId(0), 0);
    let ann;
    let wit;
    //let _route_status;
    match announced_as_path_str {
        Some(as_path_str) => {
            let communities = communities.unwrap_or("none");
            ann = Announcements::from_str(&format!(
                "e {as_path_str} 10.0.0.1 {communities} {prefix}",
            ))
            .unwrap();
            wit = Prefixes::default();
            //route_status = RouteStatus::Active;
        }
        None => {
            ann = Announcements::default();
            wit = Prefixes::new(vec![*prefix]);
            //route_status = RouteStatus::Withdrawn;
        }
    }
    let bgp_update_bytes = mk_bgp_update(&wit, &ann, &[]);

    let roto_update_msg = UpdateMessage::from_octets(
        bgp_update_bytes,
        &SessionConfig::modern(),
    )
    .unwrap();
    let rws = explode_announcements(
        &roto_update_msg,
        //&mut BTreeSet::new(),
    )
    .unwrap();
    let wdws = explode_withdrawals(
        &roto_update_msg,
        //&mut BTreeSet::new(),
    )
    .unwrap();

    let ingress_id = 1;

    let mut bulk = SmallVec::new();

    for (r, _pid) in rws {
        bulk.push(Payload::new(r, None, ingress_id, RouteStatus::Active));
    }

    for (w, _pid) in wdws {
        bulk.push(Payload::new(w, None, ingress_id, RouteStatus::Withdrawn));
    }
    Update::Bulk(Box::new(bulk))

    /*
    let afi_safi = if prefix.is_v4() { AfiSafiType::Ipv4Unicast } else { AfiSafiType::Ipv6Unicast };
    let route = RawRouteWithDeltas::new_with_message_ref(
        delta_id,
        *prefix,
        roto_update_msg,
        afi_safi,
        None,
        route_status,
    )
    .with_peer_asn(Asn::from_u32(64512))
    .with_peer_ip(IpAddr::from_str("127.0.0.1").unwrap())
    .with_router_id(MOCK_ROUTER_ID.to_string().into());
    */

    //Update::from(Payload::from(TypeValue::from(BuiltinTypeValue::Route(
    //    route,
    //))))
}

fn stored_attr_len(runner: &RibUnitRunner, prefix: &Prefix) -> usize {
    stored_record(runner, prefix).meta.as_ref().len()
}

fn stored_status(runner: &RibUnitRunner, prefix: &Prefix) -> RouteStatus {
    stored_record(runner, prefix).status
}

fn stored_record(
    runner: &RibUnitRunner,
    prefix: &Prefix,
) -> rotonda_store::prefix_record::Record<crate::payload::RotondaPaMap> {
    let match_result = runner
        .rib()
        .store()
        .unwrap()
        .match_prefix(prefix, &match_options(), &epoch::pin())
        .unwrap();

    assert!(matches!(match_result.match_type, MatchType::ExactMatch));
    assert_eq!(match_result.records.len(), 1);
    match_result.records.into_iter().next().unwrap()
}

fn match_options() -> MatchOptions {
    MatchOptions {
        match_type: MatchType::ExactMatch,
        include_withdrawn: true,
        include_less_specifics: false,
        include_more_specifics: false,
        mui: None,
        include_history: IncludeHistory::None,
    }
}

#[allow(dead_code)]
async fn is_filtered(_runner: &RibUnitRunner, _update: Update) -> bool {
    todo!() // before we start using this again, adapt it to the new codebase
            /*
            runner
                .process_update(update, |pfx, meta, store| store.insert(pfx, meta))
                .await
                .unwrap();
            let gate_metrics = runner.gate().metrics();
            let num_dropped_updates = gate_metrics.num_dropped_updates.load(SeqCst);
            let num_updates = gate_metrics.num_updates.load(SeqCst);
            num_dropped_updates == 0 && num_updates == 0
                */
}

fn query_metrics(
    status_reporter: &Arc<RibUnitStatusReporter>,
) -> (usize, usize, usize, usize, usize) {
    let metrics =
        get_testable_metrics_snapshot(&status_reporter.metrics().unwrap());
    (
        metrics.with_name::<usize>("rib_unit_num_items"),
        metrics.with_name::<usize>(
            "rib_unit_num_route_withdrawals_without_announcements",
        ),
        metrics.with_name::<usize>("rib_unit_num_routes_announced"),
        metrics.with_name::<usize>("rib_unit_num_routes_withdrawn"),
        metrics.with_name::<usize>("rib_unit_num_unique_prefixes"),
    )
}

fn mk_route_update_with_ingress(
    prefix: &Prefix,
    announced_as_path_str: Option<&str>,
    ingress_id: crate::ingress::IngressId,
) -> Update {
    let ann;
    let wit;
    match announced_as_path_str {
        Some(as_path_str) => {
            let next_hop = if prefix.is_v4() {
                "10.0.0.1"
            } else {
                "2001:db8::1"
            };
            ann = Announcements::from_str(&format!(
                "e {as_path_str} {next_hop} none {prefix}",
            ))
            .unwrap();
            wit = Prefixes::default();
        }
        None => {
            ann = Announcements::default();
            wit = Prefixes::new(vec![*prefix]);
        }
    }
    let bgp_update_bytes = mk_bgp_update(&wit, &ann, &[]);

    let roto_update_msg = UpdateMessage::from_octets(
        bgp_update_bytes,
        &SessionConfig::modern(),
    )
    .unwrap();
    let rws = explode_announcements(&roto_update_msg).unwrap();
    let wdws = explode_withdrawals(&roto_update_msg).unwrap();

    let mut bulk = SmallVec::new();

    for (r, _pid) in rws {
        bulk.push(Payload::new(r, None, ingress_id, RouteStatus::Active));
    }

    for (w, _pid) in wdws {
        bulk.push(Payload::new(w, None, ingress_id, RouteStatus::Withdrawn));
    }
    Update::Bulk(Box::new(bulk))
}

fn jsonl_ingress_ids(output: &str) -> Vec<u64> {
    output
        .lines()
        .map(|line| {
            let line: serde_json::Value = serde_json::from_str(line).unwrap();
            line["ingress"]["id"].as_u64().unwrap()
        })
        .collect()
}

#[tokio::test]
async fn test_check_filter_and_store_and_ingress_id_filtering() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();

    let mut filter = super::QueryFilter::default();

    assert!(rib
        .check_filter_and_store(AfiSafiType::Ipv4Unicast, &filter)
        .is_ok());
    assert!(rib
        .check_filter_and_store(AfiSafiType::Ipv6Unicast, &filter)
        .is_ok());

    filter.roto_function = Some("nonexistent_filter_name".to_string());
    let err = rib.check_filter_and_store(AfiSafiType::Ipv4Unicast, &filter);
    assert!(err.is_err());
    assert_eq!(
        err.unwrap_err(),
        "no roto function 'nonexistent_filter_name' defined"
    );

    rib.ingress_register
        .update_info(10, crate::ingress::IngressInfo::default());
    rib.ingress_register
        .update_info(20, crate::ingress::IngressInfo::default());

    let prefix_v4 = Prefix::from_str("192.0.2.0/24").unwrap();
    let prefix_v6 = Prefix::from_str("2001:db8::/32").unwrap();

    runner
        .process_update(mk_route_update_with_ingress(
            &prefix_v4,
            Some("[111,222]"),
            10,
        ))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update_with_ingress(
            &prefix_v4,
            Some("[111,333]"),
            20,
        ))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update_with_ingress(
            &prefix_v6,
            Some("[111,444]"),
            10,
        ))
        .await
        .unwrap();

    let mut buf = Vec::new();
    let query_filter_all = super::QueryFilter::default();
    rib.write_jsonl_stream(
        AfiSafiType::Ipv4Unicast,
        Prefix::from_str("0.0.0.0/0").unwrap(),
        query_filter_all.clone(),
        &mut buf,
    )
    .map_err(|_| "stream error")
    .unwrap();
    let output_all = String::from_utf8(buf).unwrap();
    let ids_all = jsonl_ingress_ids(&output_all);
    assert!(ids_all.contains(&10));
    assert!(ids_all.contains(&20));

    let mut buf10 = Vec::new();
    let mut query_filter_10 = super::QueryFilter::default();
    query_filter_10.ingress_id = Some(10);
    rib.write_jsonl_stream(
        AfiSafiType::Ipv4Unicast,
        Prefix::from_str("0.0.0.0/0").unwrap(),
        query_filter_10.clone(),
        &mut buf10,
    )
    .map_err(|_| "stream error")
    .unwrap();
    let output_10 = String::from_utf8(buf10).unwrap();
    let ids_10 = jsonl_ingress_ids(&output_10);
    assert!(ids_10.contains(&10));
    assert!(!ids_10.contains(&20));

    let mut buf_v6 = Vec::new();
    rib.write_jsonl_stream(
        AfiSafiType::Ipv6Unicast,
        Prefix::from_str("::/0").unwrap(),
        query_filter_all.clone(),
        &mut buf_v6,
    )
    .map_err(|_| "stream error")
    .unwrap();
    let output_v6 = String::from_utf8(buf_v6).unwrap();
    let ids_v6 = jsonl_ingress_ids(&output_v6);
    assert!(ids_v6.contains(&10));
}

/// `stream_prefix_records` (the bmp-out table-dump path) must emit exactly the
/// active records across BOTH address families and skip withdrawn ones — the
/// same set the old `prefixes_iter(&guard) + retain(!Withdrawn)` walk produced.
/// This locks in behavioural equivalence after the guard-free two-phase
/// rewrite (enumerate keys, then fetch+emit each chunk under short-lived
/// per-prefix guards with no guard held across the closure).
#[tokio::test]
async fn stream_prefix_records_emits_active_skips_withdrawn() {
    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();

    rib.ingress_register
        .update_info(10, crate::ingress::IngressInfo::default());
    rib.ingress_register
        .update_info(20, crate::ingress::IngressInfo::default());

    let pfx_v4_a = Prefix::from_str("192.0.2.0/24").unwrap();
    let pfx_v4_b = Prefix::from_str("198.51.100.0/24").unwrap();
    let pfx_v6 = Prefix::from_str("2001:db8::/32").unwrap();

    runner
        .process_update(mk_route_update_with_ingress(
            &pfx_v4_a,
            Some("[111,222]"),
            10,
        ))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update_with_ingress(
            &pfx_v4_b,
            Some("[111,333]"),
            20,
        ))
        .await
        .unwrap();
    runner
        .process_update(mk_route_update_with_ingress(
            &pfx_v6,
            Some("[111,444]"),
            10,
        ))
        .await
        .unwrap();

    // Withdraw pfx_v4_b (its only record), so it must drop out of the dump.
    runner
        .process_update(mk_route_update_with_ingress(&pfx_v4_b, None, 20))
        .await
        .unwrap();

    let mut seen: Vec<(Prefix, u32)> = Vec::new();
    let count = rib
        .stream_prefix_records(|pr| {
            for rec in &pr.meta {
                assert_ne!(
                    rec.status,
                    rotonda_store::prefix_record::RouteStatus::Withdrawn,
                    "withdrawn records must be filtered before the closure"
                );
                seen.push((pr.prefix, rec.multi_uniq_id));
            }
            true
        })
        .unwrap();

    // The two active prefixes (across both families) are emitted...
    assert!(seen.contains(&(pfx_v4_a, 10)));
    assert!(seen.contains(&(pfx_v6, 10)));
    // ...the withdrawn one is not...
    assert!(
        !seen.iter().any(|(p, _)| *p == pfx_v4_b),
        "withdrawn prefix must not be emitted"
    );
    // ...and a single walk covers both IPv4 and IPv6.
    assert!(seen.iter().any(|(p, _)| p.is_v4()));
    assert!(seen.iter().any(|(p, _)| !p.is_v4()));
    // `count` is the number of emitted prefixes (one record each here).
    assert_eq!(count, 2);
    assert_eq!(seen.len(), 2);
}

/// `gc_disconnected_bmp_peers` must reclaim idle BMP router (parent) entries,
/// not just BgpViaBmp peers — otherwise every torn-down router (incl. every
/// port scan / half-open connection that mints a childless provisional entry)
/// leaks a permanent Disconnected entry. Covers the safety invariants too:
/// a Connected router is never touched, and a router that still has a child is
/// kept until the child is gone so a reconnecting peer can still rebind.
#[tokio::test]
async fn gc_reclaims_idle_bmp_routers() {
    use crate::ingress::register::IngressState;
    use crate::ingress::{IngressInfo, IngressType};
    use std::collections::HashSet;

    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();
    let reg = &rib.ingress_register;

    let disconnected_bmp = || {
        IngressInfo::new()
            .with_ingress_type(IngressType::Bmp)
            .with_state(IngressState::Disconnected)
    };

    // id 10: childless Disconnected router (the port-scan / half-open shape).
    reg.update_info(10, disconnected_bmp());
    // id 20: Disconnected router that still owns a Disconnected child (21).
    reg.update_info(20, disconnected_bmp());
    reg.update_info(
        21,
        IngressInfo::new()
            .with_ingress_type(IngressType::BgpViaBmp)
            .with_parent_ingress(20u32)
            .with_state(IngressState::Disconnected),
    );
    // id 30: a live (Connected) router — must never be reclaimed.
    reg.update_info(
        30,
        IngressInfo::new()
            .with_ingress_type(IngressType::Bmp)
            .with_state(IngressState::Connected),
    );

    // First sweep: `prev` is empty, so the idle-interval guard reclaims
    // nothing yet — every entry must survive.
    let prev = rib.gc_disconnected_bmp_peers(HashSet::new());
    for id in [10, 20, 21, 30] {
        assert!(reg.get(id).is_some(), "id {id} reclaimed too early");
    }

    // Second sweep: 10 (childless router) and 21 (peer) were Disconnected last
    // sweep and are reclaimed. 20 still has child 21 at snapshot time, so it is
    // held. 30 is Connected and untouched.
    let prev = rib.gc_disconnected_bmp_peers(prev);
    assert!(reg.get(10).is_none(), "childless router not reclaimed");
    assert!(reg.get(21).is_none(), "BgpViaBmp peer not reclaimed");
    assert!(
        reg.get(20).is_some(),
        "router reclaimed while it still had a child"
    );
    assert!(reg.get(30).is_some(), "Connected router reclaimed");

    // Third sweep: child 21 is gone, so 20 is now childless and (having been
    // Disconnected since before the second sweep) is reclaimed. 30 stays.
    rib.gc_disconnected_bmp_peers(prev);
    assert!(
        reg.get(20).is_none(),
        "router not reclaimed after its last child was gone"
    );
    assert!(reg.get(30).is_some(), "Connected router reclaimed");
}

/// ADD-PATH path-children (`BgpPath`) flow through the record-carrying GC
/// path, and a Disconnected session is deferred while children still
/// reference it as parent: children reclaim first, the session follows one
/// sweep later. A Disconnected child of a *live* session (its path id
/// stopped being announced across a flap) is reclaimed without touching the
/// session.
#[tokio::test]
async fn gc_reclaims_path_children_then_session() {
    use crate::ingress::register::IngressState;
    use crate::ingress::{IngressInfo, IngressType};
    use std::collections::HashSet;

    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();
    let reg = &rib.ingress_register;

    let mk = |typ: IngressType,
              state: IngressState,
              parent: Option<u32>| {
        let mut info = IngressInfo::new()
            .with_ingress_type(typ)
            .with_state(state);
        if let Some(parent) = parent {
            info = info.with_parent_ingress(parent);
        }
        info
    };

    // Session 40 went down with its two path-children.
    reg.update_info(
        40,
        mk(IngressType::BgpViaBmp, IngressState::Disconnected, None),
    );
    for child in [41u32, 42] {
        reg.update_info(
            child,
            mk(IngressType::BgpPath, IngressState::Disconnected, Some(40)),
        );
    }
    // Session 50 is alive; its child 51 stopped being announced.
    reg.update_info(
        50,
        mk(IngressType::BgpViaBmp, IngressState::Connected, None),
    );
    reg.update_info(
        51,
        mk(IngressType::BgpPath, IngressState::Disconnected, Some(50)),
    );

    // First sweep: idle-interval guard, nothing reclaimed.
    let prev = rib.gc_disconnected_bmp_peers(HashSet::new());
    for id in [40, 41, 42, 50, 51] {
        assert!(reg.get(id).is_some(), "id {id} reclaimed too early");
    }

    // Second sweep: all children reclaim; session 40 is deferred because
    // 41/42 still referenced it in the snapshot; live session 50 untouched.
    let prev = rib.gc_disconnected_bmp_peers(prev);
    assert!(reg.get(41).is_none(), "path child 41 not reclaimed");
    assert!(reg.get(42).is_none(), "path child 42 not reclaimed");
    assert!(reg.get(51).is_none(), "idle child of live session kept");
    assert!(
        reg.get(40).is_some(),
        "session reclaimed while children still referenced it"
    );
    assert!(reg.get(50).is_some(), "Connected session reclaimed");

    // Third sweep: 40 is childless now and reclaims.
    rib.gc_disconnected_bmp_peers(prev);
    assert!(
        reg.get(40).is_none(),
        "session not reclaimed after its children were gone"
    );
    assert!(reg.get(50).is_some(), "Connected session reclaimed");
}

/// A router that reconnects (flips back to Connected) between sweeps must be
/// protected by the `remove_if_disconnected` guard even though it was a
/// reclaim candidate from the previous sweep.
#[tokio::test]
async fn gc_spares_router_that_reconnected_since_snapshot() {
    use crate::ingress::register::IngressState;
    use crate::ingress::{IngressInfo, IngressType};
    use std::collections::HashSet;

    let (runner, _) = RibUnitRunner::mock("").unwrap();
    let rib = runner.rib();
    let reg = &rib.ingress_register;

    reg.update_info(
        10,
        IngressInfo::new()
            .with_ingress_type(IngressType::Bmp)
            .with_state(IngressState::Disconnected),
    );

    // Mark it a candidate (Disconnected in the previous sweep).
    let prev = rib.gc_disconnected_bmp_peers(HashSet::new());
    assert!(prev.contains(&10));

    // Router reconnects before the next sweep: its entry is now Connected.
    reg.update_info(
        10,
        IngressInfo::new().with_state(IngressState::Connected),
    );

    // The sweep must not reclaim it.
    rib.gc_disconnected_bmp_peers(prev);
    assert!(
        reg.get(10).is_some(),
        "reconnected (Connected) router was reclaimed"
    );
}
