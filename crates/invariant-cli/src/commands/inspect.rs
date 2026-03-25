use clap::Args;
use invariant_core::models::profile::{JointType, SafeStopStrategy, WorkspaceBounds};
use std::path::PathBuf;

#[derive(Args)]
pub struct InspectArgs {
    #[arg(long, value_name = "PROFILE_FILE")]
    pub profile: PathBuf,
}

pub fn run(args: &InspectArgs) -> i32 {
    let profile = match invariant_core::profiles::load_from_file(&args.profile) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    println!("Profile: {}", profile.name);
    println!("Version: {}", profile.version);
    println!("Joints: {}", profile.joints.len());
    for joint in &profile.joints {
        let type_str = match joint.joint_type {
            JointType::Revolute => "revolute",
            JointType::Prismatic => "prismatic",
        };
        println!(
            "  - {} [{}] range: [{:.2}, {:.2}] max_vel: {:.2} max_torque: {:.2}",
            joint.name, type_str, joint.min, joint.max, joint.max_velocity, joint.max_torque
        );
    }

    match &profile.workspace {
        WorkspaceBounds::Aabb { min, max } => {
            println!(
                "Workspace: AABB [{}, {}, {}] to [{}, {}, {}]",
                min[0], min[1], min[2], max[0], max[1], max[2]
            );
        }
    }

    println!("Exclusion zones: {}", profile.exclusion_zones.len());
    println!("Proximity zones: {}", profile.proximity_zones.len());
    println!("Collision pairs: {}", profile.collision_pairs.len());

    match &profile.stability {
        Some(s) => {
            let enabled_str = if s.enabled { "enabled" } else { "disabled" };
            println!(
                "Stability: {} (support polygon: {} vertices, CoM height: {:.2})",
                enabled_str,
                s.support_polygon.len(),
                s.com_height_estimate
            );
        }
        None => println!("Stability: none"),
    }

    println!("Max delta time: {:.3}s", profile.max_delta_time);
    println!("Min collision distance: {:.3}m", profile.min_collision_distance);
    println!("Global velocity scale: {:.2}", profile.global_velocity_scale);
    println!("Watchdog timeout: {}ms", profile.watchdog_timeout_ms);

    let strategy_str = match profile.safe_stop_profile.strategy {
        SafeStopStrategy::ControlledCrouch => "controlled_crouch",
        SafeStopStrategy::ImmediateStop => "immediate_stop",
        SafeStopStrategy::ParkPosition => "park_position",
    };
    println!("Safe-stop strategy: {}", strategy_str);

    0
}
