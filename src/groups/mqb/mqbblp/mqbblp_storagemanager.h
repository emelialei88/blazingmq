// Copyright 2015-2023 Bloomberg Finance L.P.
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

// mqbblp_storagemanager.h                                            -*-C++-*-
#ifndef INCLUDED_MQBBLP_STORAGEMANAGER
#define INCLUDED_MQBBLP_STORAGEMANAGER

/// @file mqbblp_storagemanager.h
///
/// @brief Provide a storage manager, in charge of BlazingMQ storage.
///
/// @todo Document component
///
/// Thread Safety                               {#mqbblp_storagemanager_thread}
/// =============
///
/// Thread safe.

// MQB
#include <mqbc_clusterdata.h>
#include <mqbc_clusterstate.h>
#include <mqbc_storageutil.h>
#include <mqbcfg_messages.h>
#include <mqbconfm_messages.h>
#include <mqbi_dispatcher.h>
#include <mqbi_domain.h>
#include <mqbi_storagemanager.h>
#include <mqbnet_multirequestmanager.h>
#include <mqbs_filestore.h>
#include <mqbs_filestoreprotocol.h>
#include <mqbu_storagekey.h>

// BMQ
#include <bmqma_countingallocatorstore.h>
#include <bmqt_uri.h>

// BDE
#include <ball_log.h>
#include <bdlbb_blob.h>
#include <bdlcc_objectpool.h>
#include <bdlcc_sharedobjectpool.h>
#include <bdlmt_eventscheduler.h>
#include <bdlmt_fixedthreadpool.h>
#include <bsl_functional.h>
#include <bsl_memory.h>
#include <bsl_ostream.h>
#include <bsl_string.h>
#include <bsl_vector.h>
#include <bslma_allocator.h>
#include <bslma_managedptr.h>
#include <bslma_usesbslmaallocator.h>
#include <bslmf_nestedtraitdeclaration.h>
#include <bslmt_latch.h>
#include <bslmt_mutex.h>
#include <bsls_assert.h>
#include <bsls_atomic.h>
#include <bsls_types.h>

namespace BloombergLP {

// FORWARD DECLARATION
namespace bdlmt {
class FixedThreadPool;
}
namespace bslmt {
class Latch;
}
namespace mqbcmd {
class ClusterStorageSummary;
}
namespace mqbcmd {
class StorageCommand;
}
namespace mqbcmd {
class StorageQueueInfo;
}
namespace mqbcmd {
class StorageResult;
}
namespace mqbi {
class Cluster;
}
namespace mqbi {
class Queue;
}
namespace mqbnet {
class Cluster;
}
namespace mqbnet {
class ClusterNode;
}
namespace mqbs {
class ReplicatedStorage;
}
namespace mqbs {
class VirtualStorage;
}

namespace mqbblp {

// FORWARD DECLARATION
class RecoveryManager;
class StorageManagerIterator;

// ====================
// class StorageManager
// ====================

/// Storage Manager, in charge of all the partitions.
class StorageManager BSLS_KEYWORD_FINAL : public mqbi::StorageManager {
  private:
    // CLASS-SCOPE CATEGORY
    BALL_LOG_SET_CLASS_CATEGORY("MQBBLP.STORAGEMANAGER");

    // FRIENDS
    friend class StorageManagerIterator;

  public:
    // TYPES

    /// Pool of shared pointers to Blobs
    typedef bdlcc::SharedObjectPool<
        bdlbb::Blob,
        bdlcc::ObjectPoolFunctors::DefaultCreator,
        bdlcc::ObjectPoolFunctors::RemoveAll<bdlbb::Blob> >
        BlobSpPool;

    typedef bsl::vector<mqbnet::ClusterNode*> ClusterNodes;

  private:
    // PRIVATE CONSTANTS

    /// For brevity.
    static const int k_KEY_LEN = mqbs::FileStoreProtocol::k_KEY_LENGTH;

  private:
    // PRIVATE TYPES
    typedef bdlmt::EventScheduler::RecurringEventHandle RecurringEventHandle;

    typedef mqbc::StorageUtil::FileStores FileStores;

    typedef bslma::ManagedPtr<RecoveryManager> RecoveryManagerMp;

    typedef bsl::vector<unsigned int> PrimaryLeaseIds;

    typedef mqbi::StorageManager_PartitionInfo PartitionInfo;
    typedef bsl::vector<PartitionInfo>         PartitionInfoVec;

    typedef bsl::function<void(int, const PrimaryLeaseIds&)> RecoveryStatusCb;

    typedef bsl::shared_ptr<bdlbb::Blob> BlobSp;

    typedef mqbs::DataStoreConfig::QueueKeyInfoMap QueueKeyInfoMap;

    typedef mqbc::ClusterStatePartitionInfo ClusterStatePartitionInfo;

    typedef mqbc::ClusterData::RequestManagerType RequestManagerType;

    typedef mqbc::ClusterData::MultiRequestManagerType MultiRequestManagerType;

    typedef MultiRequestManagerType::RequestContextSp RequestContextSp;

    typedef MultiRequestManagerType::NodeResponsePair  NodeResponsePair;
    typedef MultiRequestManagerType::NodeResponsePairs NodeResponsePairs;
    typedef MultiRequestManagerType::NodeResponsePairsIter
        NodeResponsePairsIter;
    typedef MultiRequestManagerType::NodeResponsePairsConstIter
        NodeResponsePairsConstIter;

    typedef mqbc::StorageUtil::DomainQueueMessagesCountMaps
        DomainQueueMessagesCountMaps;

  private:
    // DATA

    /// Allocator to use.
    bslma::Allocator* d_allocator_p;

    /// Allocatro store to spawn new allocators for sub-components.
    bmqma::CountingAllocatorStore d_allocators;

    bsls::AtomicBool d_isStarted;

    /// Flag to denote if a low disk space warning was issued.  This flag is
    /// used *only* for logging purposes (see `storageMonitorCb` impl).
    bool d_lowDiskspaceWarning;

    /// Mutex to protect access to `d_unrecognizedDomains` and its elements.
    bslmt::Mutex d_unrecognizedDomainsLock;

    /// List of `DomainQueueMessagesMap`, indexed by `partitionId`.
    ///
    /// Each `DomainQueueMessagesMap` is a map of `unrecognized domain name ->
    /// queue messages info` found during storage recovery, either due to
    /// genuine domain migration or misconfiguration.
    DomainQueueMessagesCountMaps d_unrecognizedDomains;

    /// `SharedObjectPool` of blobs to use.
    BlobSpPool* d_blobSpPool_p;

    /// Domain factory to use.
    mqbi::DomainFactory* d_domainFactory_p;

    /// Dispatcher to use.
    mqbi::Dispatcher* d_dispatcher_p;

    /// Cluster config to use.
    const mqbcfg::ClusterDefinition& d_clusterConfig;

    mqbi::Cluster* d_cluster_p;

    mqbc::ClusterData* d_clusterData_p;

    const mqbc::ClusterState& d_clusterState;

    /// Recovery manager.  Empty if this is a local cluster.
    RecoveryManagerMp d_recoveryManager_mp;

    /// List of all partitions, indexed by `partitionId`.
    FileStores d_fileStores;

    /// Thread pool used for any standalone work that can be offloaded to
    /// non-partition-dispatcher therads.  It is used by the partitions owned
    /// by this object.
    bdlmt::FixedThreadPool* d_miscWorkThreadPool_p;

    /// Number of partitions whose recovery has been fully completed by the
    /// recovery manager.  This variable needs to be atomic because it's
    /// touched from the dispatcher threads of all partitions.
    bsls::AtomicInt d_numPartitionsRecoveredFully;

    /// Number of partitions which have completed recovery of file-backed
    /// queues and their virtual storages.  This variable needs to be atomic
    /// because it's touched from the dispatched threads of all partitions.
    bsls::AtomicInt d_numPartitionsRecoveredQueues;

    RecoveryStatusCb d_recoveryStatusCb;

    PartitionPrimaryStatusCb d_partitionPrimaryStatusCb;

    /// Mutex to protect access to `d_storages` and its elements.  See
    /// documentation for `d_storages`.
    mutable bslmt::Mutex d_storagesLock;

    /// Vector of `CanonicalQueueUri -> ReplicatedStorage` maps.  Vector is
    /// indexed by partitionId.  The maps contain *both* in-memory and
    /// file-backed storages.  Note that `d_storagesLock` must be held while
    /// accessing this container and any of its elements (`URI -> Storage`
    /// maps), because they are accessed from partitions' dispatcher threads,
    /// as well as the cluster dispatcher thread.
    StorageSpMapVec d_storages;

    RecurringEventHandle d_storageMonitorEventHandle;

    RecurringEventHandle d_gcMessagesEventHandle;

    /// `PrimaryLeaseIds` recovered from each partition.  Each element in this
    /// vector represents the recovered primaryLeaseId for the partition at
    /// that index.  Each element in this vector is modified once in
    /// `onPartitionRecovery` in the dispatcher therad associated with the
    /// partition (i.e., index of the element).  This variable is not used once
    /// this storage manager has notified the upper layer of its recovery
    /// status via `d_recoveryStatusCb`.
    PrimaryLeaseIds d_recoveredPrimaryLeaseIds;

    /// Vector of `PartitionInfo` indexed by partitionId.  An element in this
    /// container represents the *latest* primaryNode, leaseId, and status for
    /// the partitionId at that element's index.
    PartitionInfoVec d_partitionInfoVec;

    bsls::Types::Uint64 d_minimumRequiredDiskSpace;

    /// Replication factor used to configure `FileStores`.
    int d_replicationFactor;

  private:
    /// Not implemented.
    StorageManager(const StorageManager&) BSLS_KEYWORD_DELETED;

    /// Not implemented.
    StorageManager& operator=(const StorageManager&) BSLS_KEYWORD_DELETED;

  private:
    // PRIVATE MANIPULATORS

    /// Perform recovery of partition with specified `partitionId` assigned
    /// to the dispatcher thread identified by the specified `processorId`.
    void startRecoveryCb(int partitionId);

    /// Callback executed by `mqbblp::RecoveryManager` after recovery for
    /// the specified `partitionId` is complete with the specified `status`,
    /// having the specified `recoveryEvents` and `recoveryPeer`.  Executed
    /// by the dispatcher thread associated with `partitionId`.
    void onPartitionRecovery(int                        partitionId,
                             int                        status,
                             const bsl::vector<BlobSp>& recoveryEvents,
                             mqbnet::ClusterNode*       recoveryPeer,
                             bsls::Types::Int64         recoveryStartTime);

    /// Callback executed by `mqbblp::RecoveryManager` after primary sync
    /// for the specified `partitionId` is complete with the specified
    /// `status`.
    ///
    /// THREAD: Executed by the dispatcher thread associated with
    ///         'partitionId'.
    void onPartitionPrimarySync(int partitionId, int status);

    /// Gracefully shut down the partition associated with the specified
    /// `partitionId` assigned to the dispatcher thread identified by the
    /// specified `processorId`, and arrive on the specified `latch` when
    /// shut down is complete..  Executed by the dispatcher thread
    /// associated with `processorId`.
    void shutdownCb(int partitionId, bslmt::Latch* latch);

    /// Callback executed when the partition having the specified
    /// `partitionId` has performed recovery and recovered file-backed
    /// queues and their virtual storages in the specified
    /// `queueKeyInfoMap`.
    ///
    /// THREAD: Executed by the dispatcher thread of the partition.
    void recoveredQueuesCb(int                    partitionId,
                           const QueueKeyInfoMap& queueKeyInfoMap);

    /// Executed by queue/file-store dispatcher thread.
    void setPrimaryForPartitionDispatched(int                  partitionId,
                                          mqbnet::ClusterNode* primaryNode,
                                          unsigned int         primaryLeaseId,
                                          const ClusterNodes&  peers);

    /// Executed by queue/file-store dispatcher thread.
    void clearPrimaryForPartitionDispatched(int                  partitionId,
                                            mqbnet::ClusterNode* primary);

    /// Executed by queue/file-store dispatcher thread.
    void
    processStorageEventDispatched(int partitionId,
                                  const bsl::shared_ptr<bdlbb::Blob>& blob,
                                  mqbnet::ClusterNode*                source);

    /// Executed in cluster dispatcher thread.
    void processPartitionSyncEvent(const mqbi::DispatcherStorageEvent& event);

    /// Executed by queue/file-store dispatcher thread.
    void processPartitionSyncEventDispatched(
        int                                 partitionId,
        const bsl::shared_ptr<bdlbb::Blob>& blob,
        mqbnet::ClusterNode*                source);

    /// Executed by queue/file-store dispatcher thread.
    void processStorageSyncRequestDispatched(
        int                                 partitionId,
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source);

    /// Executed by queue/file-store dispatcher thread.
    void processPartitionSyncStateRequestDispatched(
        int                                 partitionId,
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source);

    /// Executed by queue/file-store dispatcher thread.
    void processPartitionSyncDataRequestDispatched(
        int                                 partitionId,
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source);

    /// Executed by queue/file-store dispatcher thread.
    void processPartitionSyncDataRequestStatusDispatched(
        int                                 partitionId,
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source);

    void processShutdownEventDispatched(int partitionId);

    /// Explicitly call `flush` on all FileStores to enforce their GC.
    void forceFlushFileStores();

  public:
    // TRAITS
    BSLMF_NESTED_TRAIT_DECLARATION(StorageManager, bslma::UsesBslmaAllocator)

    // CREATORS

    /// Create a new `StorageManager` using the specified `allocator` and
    /// suplying to it the specified `blobBufferFactory`.
    StorageManager(const mqbcfg::ClusterDefinition& clusterConfig,
                   mqbi::Cluster*                   cluster,
                   mqbc::ClusterData*               clusterData,
                   const mqbc::ClusterState&        clusterState,
                   const RecoveryStatusCb&          recoveryStatusCb,
                   const PartitionPrimaryStatusCb&  partitionPrimaryStatusCb,
                   mqbi::DomainFactory*             domainFactory,
                   mqbi::Dispatcher*                dispatcher,
                   bdlmt::FixedThreadPool*          threadPool,
                   bslma::Allocator*                allocator);

    /// Destructor
    ~StorageManager() BSLS_KEYWORD_OVERRIDE;

    // MANIPULATORS

    /// Start this storage manager.  Return 0 on success, or a non-zero rc
    /// otherwise, populating the specified `errorDescription` with a
    /// description of the error.
    ///
    /// THREAD: Executed by the cluster's dispatcher thread.
    int start(bsl::ostream& errorDescription) BSLS_KEYWORD_OVERRIDE;

    /// Stop this storage manager.
    void stop() BSLS_KEYWORD_OVERRIDE;

    /// Initialize the queue key info map based on information in the specified
    /// `clusterState`.  Note that this method should only be called once;
    /// subsequent calls will be ignored.
    void initializeQueueKeyInfoMap(const mqbc::ClusterState& clusterState)
        BSLS_KEYWORD_OVERRIDE;

    /// Register a queue with the specified `uri`, `queueKey` and
    /// `partitionId`, having the specified `appIdKeyPairs`, and belonging
    /// to the specified `domain`.  Load into the specified `storage` the
    /// associated queue storage created.
    ///
    /// THREAD: Executed by the Client's dispatcher thread.
    void registerQueue(const bmqt::Uri&        uri,
                       const mqbu::StorageKey& queueKey,
                       int                     partitionId,
                       const AppInfos&         appIdKeyPairs,
                       mqbi::Domain*           domain) BSLS_KEYWORD_OVERRIDE;

    /// Synchronously unregister the queue with the specified `uri` from the
    /// specified `partitionId`.  Behavior is undefined unless this routine
    /// is invoked from the cluster dispatcher thread.
    ///
    /// THREAD: Executed by the Client's dispatcher thread.
    void unregisterQueue(const bmqt::Uri& uri,
                         int              partitionId) BSLS_KEYWORD_OVERRIDE;

    /// Configure the fanout queue having specified `uri` and `queueKey`,
    /// assigned to the specified `partitionId` to have the specified
    /// `addedIdKeyPairs` appId/appKey pairs added and `removedIdKeyPairs`
    /// appId/appKey pairs removed.  Return zero on success, and non-zero
    /// value otherwise.  Behavior is undefined unless this function is
    /// invoked at the primary node.  Behavior is also undefined unless the
    /// queue is configured in fanout mode.
    ///
    /// THREAD: Executed by the Queue's dispatcher thread.
    int updateQueuePrimary(const bmqt::Uri&        uri,
                           const mqbu::StorageKey& queueKey,
                           int                     partitionId,
                           const AppInfos&         addedIdKeyPairs,
                           const AppInfos&         removedIdKeyPairs)
        BSLS_KEYWORD_OVERRIDE;

    void
    registerQueueReplica(int                     partitionId,
                         const bmqt::Uri&        uri,
                         const mqbu::StorageKey& queueKey,
                         mqbi::Domain*           domain = 0,
                         bool allowDuplicate = false) BSLS_KEYWORD_OVERRIDE;

    void unregisterQueueReplica(int                     partitionId,
                                const bmqt::Uri&        uri,
                                const mqbu::StorageKey& queueKey,
                                const mqbu::StorageKey& appKey)
        BSLS_KEYWORD_OVERRIDE;

    void updateQueueReplica(int                     partitionId,
                            const bmqt::Uri&        uri,
                            const mqbu::StorageKey& queueKey,
                            const AppInfos&         appIdKeyPairs,
                            mqbi::Domain*           domain = 0,
                            bool allowDuplicate = false) BSLS_KEYWORD_OVERRIDE;

    /// Set the queue instance associated with the file-backed storage for
    /// the specified `uri` mapped to the specified `partitionId` to the
    /// specified `queue` value.  Note that this method *does* *not*
    /// synchronize on the queue-dispatcher thread.
    void setQueue(mqbi::Queue*     queue,
                  const bmqt::Uri& uri,
                  int              partitionId) BSLS_KEYWORD_OVERRIDE;

    /// Set the queue instance associated with the file-backed storage for
    /// the specified `uri` mapped to the specified `partitionId` to the
    /// specified `queue` value.  Behavior is undefined unless `queue` is
    /// non-null or unless this routine is invoked from the dispatcher
    /// thread associated with the `partitionId`.
    void setQueueRaw(mqbi::Queue*     queue,
                     const bmqt::Uri& uri,
                     int              partitionId) BSLS_KEYWORD_OVERRIDE;

    /// Behavior is undefined unless the specified 'partitionId' is in range
    /// and the specified 'primaryNode' is not null.
    ///
    /// THREAD: Executed in cluster dispatcher thread.
    void
    setPrimaryForPartition(int                  partitionId,
                           mqbnet::ClusterNode* primaryNode,
                           unsigned int primaryLeaseId) BSLS_KEYWORD_OVERRIDE;

    /// Behavior is undefined unless the specified 'partitionId' is in range
    /// and the specified 'primaryNode' is not null.
    ///
    /// THREAD: Executed in cluster dispatcher thread.
    void clearPrimaryForPartition(int                  partitionId,
                                  mqbnet::ClusterNode* primary)
        BSLS_KEYWORD_OVERRIDE;

    /// Set the primary status of the specified 'partitionId' to the specified
    /// 'value'.
    ///
    /// THREAD: Executed in cluster dispatcher thread.
    void setPrimaryStatusForPartition(int partitionId,
                                      bmqp_ctrlmsg::PrimaryStatus::Value value)
        BSLS_KEYWORD_OVERRIDE;

    /// Process primary state request received from the specified `source`
    /// with the specified `message`.
    void processPrimaryStateRequest(
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source) BSLS_KEYWORD_OVERRIDE;

    void processReplicaStateRequest(
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source) BSLS_KEYWORD_OVERRIDE;

    /// Process replica data request received from the specified `source`
    /// with the specified `message`.
    void processReplicaDataRequest(const bmqp_ctrlmsg::ControlMessage& message,
                                   mqbnet::ClusterNode*                source)
        BSLS_KEYWORD_OVERRIDE;

    int makeStorage(bsl::ostream&                      errorDescription,
                    bsl::shared_ptr<mqbi::Storage>*    out,
                    const bmqt::Uri&                   uri,
                    const mqbu::StorageKey&            queueKey,
                    int                                partitionId,
                    const bsls::Types::Int64           messageTtl,
                    const int                          maxDeliveryAttempts,
                    const mqbconfm::StorageDefinition& storageDef)
        BSLS_KEYWORD_OVERRIDE;

    /// Executed in cluster dispatcher thread.
    void processStorageEvent(const mqbi::DispatcherStorageEvent& event)
        BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void processStorageSyncRequest(const bmqp_ctrlmsg::ControlMessage& message,
                                   mqbnet::ClusterNode*                source)
        BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void processPartitionSyncStateRequest(
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source) BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void processPartitionSyncDataRequest(
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source) BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void processPartitionSyncDataRequestStatus(
        const bmqp_ctrlmsg::ControlMessage& message,
        mqbnet::ClusterNode*                source) BSLS_KEYWORD_OVERRIDE;

    /// Executed in cluster dispatcher thread.
    void processRecoveryEvent(const mqbi::DispatcherRecoveryEvent& event)
        BSLS_KEYWORD_OVERRIDE;

    /// Executed in IO thread.
    void
    processReceiptEvent(const bmqp::Event&   event,
                        mqbnet::ClusterNode* source) BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void bufferPrimaryStatusAdvisory(
        const bmqp_ctrlmsg::PrimaryStatusAdvisory& advisory,
        mqbnet::ClusterNode* source) BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void processPrimaryStatusAdvisory(
        const bmqp_ctrlmsg::PrimaryStatusAdvisory& advisory,
        mqbnet::ClusterNode* source) BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void processReplicaStatusAdvisory(int                  partitionId,
                                      mqbnet::ClusterNode* source,
                                      bmqp_ctrlmsg::NodeStatus::Value status)
        BSLS_KEYWORD_OVERRIDE;

    /// Executed by any thread.
    void processShutdownEvent() BSLS_KEYWORD_OVERRIDE;

    /// Invoke the specified `functor` with each queue associated to the
    /// partition identified by the specified `partitionId` if that
    /// partition has been successfully opened.  The behavior is undefined
    /// unless invoked from the queue thread corresponding to `partitionId`.
    void
    applyForEachQueue(int                 partitionId,
                      const QueueFunctor& functor) const BSLS_KEYWORD_OVERRIDE;

    /// Process the specified `command`, and load the result to the
    /// specified `result`.  Return 0 if the command was successfully
    /// processed, or a non-zero value otherwise.  This function can be
    /// invoked from any thread, and will block until the potentially
    /// asynchronous operation is complete.
    int processCommand(mqbcmd::StorageResult*        result,
                       const mqbcmd::StorageCommand& command)
        BSLS_KEYWORD_OVERRIDE;

    /// GC the queues from unrecognized domains, if any.
    void gcUnrecognizedDomainQueues() BSLS_KEYWORD_OVERRIDE;

    /// Purge the queues on a given domain.
    int
    purgeQueueOnDomain(mqbcmd::StorageResult* result,
                       const bsl::string& domainName) BSLS_KEYWORD_OVERRIDE;

    // ACCESSORS

    /// Return the processor handle in charge of the specified
    /// `partitionId`.  The behavior is undefined if `partitionId` does not
    /// represent a valid partition id.
    mqbi::Dispatcher::ProcessorHandle
    processorForPartition(int partitionId) const BSLS_KEYWORD_OVERRIDE;

    /// Return true if the queue having specified `uri` and assigned to the
    /// specified `partitionId` has no messages, false in any other case.
    /// Behavior is undefined unless this routine is invoked from cluster
    /// dispatcher thread.
    bool isStorageEmpty(const bmqt::Uri& uri,
                        int partitionId) const BSLS_KEYWORD_OVERRIDE;

    /// Return partition corresponding to the specified `partitionId`.  The
    /// behavior is undefined if `partitionId` does not represent a valid
    /// partition id.
    const mqbs::FileStore&
    fileStore(int partitionId) const BSLS_KEYWORD_OVERRIDE;

    bslma::ManagedPtr<mqbi::StorageManagerIterator>
    getIterator(int partitionId) const BSLS_KEYWORD_OVERRIDE;
};

// ============================
// class StorageManagerIterator
// ============================

/// Provide thread safe iteration through all the storages of a partition in
/// the storage manager.  The order of the iteration is implementation
/// defined.  An iterator is *valid* if it is associated with a storage in
/// the manager, otherwise it is *invalid*.  Thread-safe iteration is
/// provided by locking the manager during the iterator's construction and
/// unlocking it at the iterator's destruction.  This guarantees that during
/// the life time of an iterator, the manager can't be modified.
class StorageManagerIterator BSLS_KEYWORD_FINAL
: public mqbi::StorageManagerIterator {
  private:
    // PRIVATE TYPES
    typedef StorageManager::StorageSpMap          StorageSpMap;
    typedef StorageManager::StorageSpMapConstIter StorageMapConstIter;

  private:
    // DATA
    const StorageManager* d_manager_p;

    const StorageSpMap* d_map_p;

    StorageMapConstIter d_iterator;

  private:
    // NOT IMPLEMENTED
    StorageManagerIterator(const StorageManagerIterator&) BSLS_KEYWORD_DELETED;
    StorageManagerIterator&
    operator=(const StorageManagerIterator&) BSLS_KEYWORD_DELETED;

  public:
    // CREATORS

    /// Create an iterator for the specified `partitionId` in the specified
    /// storage `manager` and associated it with the first storage of the
    /// `partitionId`.  If the `manager` is empty then the iterator is
    /// initialized to be invalid.  The `manager` is locked for the duration
    /// of iterator's life time.  The behavior is undefined unless
    /// `partitionId` is valid and `manager` is not null.
    StorageManagerIterator(int partitionId, const StorageManager* manager);

    /// Destroy this iterator and unlock the storage manager associated with
    /// it.
    ~StorageManagerIterator() BSLS_KEYWORD_OVERRIDE;

    // MANIPULATORS

    /// Advance this iterator to refer to the next storage of the associated
    /// partition; if there is no next storage in the associated partition,
    /// then this iterator becomes *invalid*.  The behavior is undefined
    /// unless this iterator is valid.  Note that the order of the iteration
    /// is not specified.
    void operator++() BSLS_KEYWORD_OVERRIDE;

    // ACCESSORS

    /// Return non-zero if the iterator is *valid*, and 0 otherwise.
    operator const void*() const BSLS_KEYWORD_OVERRIDE;

    /// Return a reference offering non-modifiable access to the queue URI
    /// being pointed by this iterator.  The behavior is undefined unless
    /// the iterator is *valid*.
    const bmqt::Uri& uri() const BSLS_KEYWORD_OVERRIDE;

    /// Return a reference offering non-modifiable access to the storage
    /// being pointed by this iterator.  The behavior is undefined unless
    /// the iterator is *valid*. Note that since iterator is not a first
    /// class object, its okay to pass a raw pointer.
    const mqbs::ReplicatedStorage* storage() const BSLS_KEYWORD_OVERRIDE;
};

// --------------------
// class StorageManager
// --------------------

// PUBLIC ACCESSORS
inline mqbi::Dispatcher::ProcessorHandle
StorageManager::processorForPartition(int partitionId) const
{
    // executed by *ANY* thread

    // PRECONDITIONS
    BSLS_ASSERT_SAFE(0 <= partitionId &&
                     partitionId < static_cast<int>(d_fileStores.size()));

    return d_fileStores[partitionId]->processorId();
}

inline const mqbs::FileStore& StorageManager::fileStore(int partitionId) const
{
    // executed by *ANY* thread

    // PRECONDITIONS
    BSLS_ASSERT_SAFE(0 <= partitionId &&
                     partitionId < static_cast<int>(d_fileStores.size()));

    return *d_fileStores[partitionId].get();
}

inline bslma::ManagedPtr<mqbi::StorageManagerIterator>
StorageManager::getIterator(int partitionId) const
{
    bslma::ManagedPtr<mqbi::StorageManagerIterator> mp(
        new (*d_allocator_p) StorageManagerIterator(partitionId, this),
        d_allocator_p);

    return mp;
}

// ----------------------------
// class StorageManagerIterator
// ----------------------------

// CREATORS
inline StorageManagerIterator::StorageManagerIterator(
    int                   partitionId,
    const StorageManager* manager)
: d_manager_p(manager)
, d_map_p(0)
, d_iterator()
{
    // PRECONDITIONS
    BSLS_ASSERT_SAFE(d_manager_p);
    BSLS_ASSERT_SAFE(0 <= partitionId);

    d_map_p = &(d_manager_p->d_storages[partitionId]);
    BSLS_ASSERT_SAFE(d_map_p);

    d_manager_p->d_storagesLock.lock();  // LOCK
    d_iterator = d_map_p->begin();
}

// MANIPULATORS
inline void StorageManagerIterator::operator++()
{
    ++d_iterator;
}

// ACCESSORS
inline StorageManagerIterator::operator const void*() const
{
    return (d_iterator == d_map_p->end())
               ? 0
               : const_cast<StorageManagerIterator*>(this);
}

inline const bmqt::Uri& StorageManagerIterator::uri() const
{
    // PRECONDITIONS
    BSLS_ASSERT_SAFE(*this);
    return d_iterator->first;
}

inline const mqbs::ReplicatedStorage* StorageManagerIterator::storage() const
{
    // PRECONDITIONS
    BSLS_ASSERT_SAFE(*this);
    return (d_iterator->second).get();
}

}  // close package namespace
}  // close enterprise namespace

#endif
