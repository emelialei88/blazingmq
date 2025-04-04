// Copyright 2017-2023 Bloomberg Finance L.P.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// mqbblp_clusterstatemonitor.h                                       -*-C++-*-
#ifndef INCLUDED_MQBBLP_CLUSTERSTATEMONITOR
#define INCLUDED_MQBBLP_CLUSTERSTATEMONITOR

/// @file mqbblp_clusterstatemonitor.h
///
/// @brief Provide a mechanism to monitor the cluster state.
///
/// @bbref{mqbblp::ClusterStateMonitor} monitors the overall state of a cluster
/// and invokes associated callbacks when it is considered bad for an extended
/// period of time.  Various attributes contribute to the cluster state, and
/// each of them is monitored through the help of the
/// @bbref{mqbblp::ClusterStateMonitorState} object.  The following attributes
/// are monitored:
///
///   * leader:  the leader must be active
///   * primary: each partition must have an active primary
///   * node:    each node must either be disconnected, or in available status
///
/// Note that @bbref{bmqsys::TimeUtil::initialize()} must have been called
/// prior to the start of this component

// MQB
#include <mqbc_clustermembership.h>
#include <mqbc_clusterstate.h>
#include <mqbi_dispatcher.h>

// BDE
#include <bdlmt_eventscheduler.h>
#include <bsl_functional.h>
#include <bsl_string.h>
#include <bsl_vector.h>
#include <bsls_assert.h>
#include <bsls_platform.h>
#include <bsls_timeinterval.h>

namespace BloombergLP {

// FORWARD DECLARE
namespace mqbc {
class ClusterData;
}
namespace mqbc {
class ClusterStateObserver;
}

namespace mqbblp {

// =========================
// class ClusterStateMonitor
// =========================

/// Monitor and alarm on the cluster state.
class ClusterStateMonitor {
  private:
    // CLASS-SCOPE CATEGORY
    BALL_LOG_SET_CLASS_CATEGORY("MQBBLP.CLUSTERSTATEMONITOR");

  public:
    /// Enum to signify which state a given attribute is in.
    enum StateType {
        /// State is invalid but within allowed max invalid time.
        e_INVALID,
        /// State has been invalid above a pre-alarm threshold but within
        /// allowed max invalid time.
        e_THRESHOLD,
        /// State is valid
        e_VALID,
        /// State has been invalid for more than allowed max invalid time and
        /// is now alarming.
        e_ALARMING
    };

  private:
    // PRIVATE TYPES
    typedef mqbc::ClusterMembership::ClusterNodeSessionMap
                                                        ClusterNodeSessionMap;
    typedef bdlmt::EventScheduler::RecurringEventHandle RecurringEventHandle;

    /// Struct holding the state context of a monitored cluster attribute
    struct State {
        /// Max allowed time in inactive state.
        bsls::TimeInterval d_maxInvalid;

        /// Max allowed time in inactive state before reaching the threshold
        /// state.
        bsls::TimeInterval d_maxThreshold;

        /// Last time the status was valid.
        bsls::TimeInterval d_lastValid;

        /// Last time a threshold notification was emitted.
        bsls::TimeInterval d_lastThreshold;

        /// Last time an alarm notification was emitted.
        bsls::TimeInterval d_lastAlarm;

        /// Current state for this attribute.
        StateType d_state;

        /// Create a new object representing a State having the specified
        /// `maxInvalid`, `maxThreshold`, `lastInvalid` and `state`.
        State();
        State(const bsls::TimeInterval& maxInvalid,
              const bsls::TimeInterval& maxThreshold,
              const bsls::TimeInterval& lastValid,
              const StateType&          state);
    };

    /// Vector of partitions
    typedef bsl::vector<State> PartitionStates;

    /// Set of observers
    typedef bsl::unordered_set<mqbc::ClusterStateObserver*> ObserversSet;

    /// Map of node id to state
    typedef bsl::unordered_map<int, State> NodeStatesMap;

    /// Enum to signify if the healthiness of the cluster has changed.
    enum StateTransition {
        /// State has transitioned to a healthy state.
        e_HEALTHY,
        /// State has transitioned to a threshold state.
        e_THRESHOLD_REACHED,
        /// State has transitioned to a bad state.
        e_BAD,
        e_NO_CHANGE
    };

  private:
    // DATA

    /// Are we started?
    bool d_isStarted;

    /// Boolean to signify if this cluster is in a healthy state.  Note that
    /// this updates instantaneously rather than after the state is `ALARMING`
    /// which has a lag time as configured with the constants.
    bool d_isHealthy;

    /// Indicates whether we already alarmed: this component monitors multiple
    /// attributes, the first time *any* goes bad, cluster state is considered
    /// in "bad" state.  This boolean is to prevent firing for each attribute
    /// transitioning to bad state.
    bool d_hasAlarmed;

    /// Indicates whether we already reached the threshold for notifying
    /// observers about the invalid state of the cluster (as perceived by this
    /// node): this component monitors multiple attributes, the first time
    /// *any* reaches the threshold amount of time in invalid state, we
    /// consider this "global" threshold to have been reached.  This boolean is
    /// to prevent firing for each attribute transitioning to "threshold
    /// reached" state.
    bool d_thresholdReached;

    /// State of the leader.
    State d_leaderState;

    /// Map of node description to state of each node.
    NodeStatesMap d_nodeStates;

    /// Map of partitionId to state of each partition.
    PartitionStates d_partitionStates;

    /// State of failover process.
    State d_failoverState;

    /// Pointer to scheduler.
    bdlmt::EventScheduler* d_scheduler_p;

    /// Event handle for recurring `verifyAllStates()`.
    RecurringEventHandle d_eventHandle;

    /// The non-persistent state of a cluster.
    mqbc::ClusterData* d_clusterData_p;

    /// Pointer to cluster state object.
    const mqbc::ClusterState* d_clusterState_p;

    /// Observers of cluster state threshold notifications.
    ObserversSet d_observers;

  private:
    // PRIVATE MANIPULATORS

    /// Helper method to determine if there is a threshold notification to
    /// emit and, if so, invoke the specified `notificationCb` on all
    /// observers.
    ///
    /// THREAD: This method is called from the Cluster's dispatcher thread.
    void notifyObserversIfNeededHelper(
        State*                                                  state,
        bool*                                                   shouldAlarm,
        const bsl::function<void(mqbc::ClusterStateObserver*)>& notificationCb,
        int                                                     thresholdTime,
        int                                                     maxTime,
        bsls::TimeInterval                                      now);

    /// Query the states map and notify all registered observers if there
    /// are any threshold notifications to emit.
    ///
    /// THREAD: This method is called from the Cluster's dispatcher thread.
    void notifyObserversIfNeeded();

    /// Update the specified `state` object with the new `isValid` state
    /// corresponding to the status of the attribute at the `now` time, and
    /// return an enum value representing the state transition which may
    /// have happened as a result of the new computed state of the
    /// attribute.
    ///
    /// THREAD: This method is called from the Cluster's dispatcher thread.
    StateTransition
    checkAndUpdateState(State* state, bool isValid, bsls::TimeInterval now);

    /// THREAD: This method is called from the any thread.
    void verifyAllStates();

    /// Query the cluster state and update the states map to reflect any
    /// changes.
    ///
    /// THREAD: This method is called from the Cluster's dispatcher thread.
    void verifyAllStatesDispatched();

    /// Get the dispatcher pointer.
    mqbi::Dispatcher* dispatcher();

    /// Get the dispatcherClient pointer.
    mqbi::DispatcherClient* dispatcherClient();

    /// Alarm if the specified `state` has changed to e_ALARMING and print
    /// useful information on other changes in state.
    ///
    /// THREAD: This method is called from the Cluster's dispatcher thread.
    void onMonitorStateChange(const StateType& state);

  public:
    // CREATORS

    /// Create a new object representing a cluster monitor having the
    /// specified `clusterState`, and `scheduler`.  Use the specified
    /// `allocator` for any memory allocation.
    ClusterStateMonitor(mqbc::ClusterData*        clusterData,
                        const mqbc::ClusterState* clusterState,
                        bslma::Allocator*         allocator);

    /// Destructor
    ~ClusterStateMonitor();

    // MANIPULATORS

    /// Start the monitor.
    void start();

    /// Register the specified `observer` to be notified of threshold state
    /// notifications.
    ///
    /// THREAD: This method should only be called from the associated
    /// cluster's dispatcher thread.
    void registerObserver(mqbc::ClusterStateObserver* observer);

    /// Un-register the specified `observer` from being notified of state
    /// changes.
    ///
    /// THREAD: This method should only be called from the associated
    /// cluster's dispatcher thread.
    void unregisterObserver(mqbc::ClusterStateObserver* observer);

    /// Stop the monitor.
    void stop();

    // ACCESSORS

    /// Return true if the monitored cluster is in a valid state, which
    /// implies that the leader state is valid and each partition state is
    /// valid, and false otherwise.
    bool isHealthy() const;
};

// ============================================================================
//                             INLINE DEFINITIONS
// ============================================================================

// -------------------------
// class ClusterStateMonitor
// -------------------------

inline bool ClusterStateMonitor::isHealthy() const
{
    return d_isHealthy;
}

}  // close package namespace
}  // close enterprise namespace

#endif
