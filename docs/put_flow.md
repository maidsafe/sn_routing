# Workflow for putting data to Vault Network
Client send a put request to network which will be handled by its correspondent ClientManager first.
The ClientManager will check whether such put request is allowed.
If allowed, the correspondent Primary, Backup and Sacrificial copy of such data will be passed to DataManagers.
DMs will pickup PmidNode to store the data and pmid_node's PmidManagers will be notified first.
PmidManagers updates account info of pmid_node and pass the put request further to it.
When PmidNode doesn't have enough space to store the copy, it will try to remove the Sacrificial it holds to free up some space if the incoming copy is Primary.
For each removed Sacrificial copy, a PutFailure will be sent out from PmidNode to PmidManager then to DataManager to ensure each persona get proper informed.


###Put(D)
_Client_   =>> |__ClientManager__ (Primary, Backup, Sacrificial)[Allow ? So : PutFailure]
          *->> |__DataManager__  [Exist(D) ? Terminate_Flow : {AddPmid.Sy, So}]
          *->> |__PmidManager__ {Put.Sy, So}
          *->  |_PmidNode_ [Store ? Flow_Completed_and_Reply : Primary? TryToRemoveSacrificial : PutFailure]

Note : with the current routing API design, the put request of Backup and Sacrificial copies will be sent using the same put request as Primary.
However, the DestinationAddress will be used to differentiate the different type of copy.
i.e. requiring a hash verification process in DataManager and PmidNode to replace the data_name
Note : an active discussion remains whether Put flow needs to Reply on success.

--
#####MaidManager::PutFailure
__ClientManager__ *-> |_Client_

--
#####PmidNode::PutFailure
_PmidNode_ ->> |__PmidManager__ {Delete.Sy, So}
          *->> |__DataManager__ { [Value.Pmids.Count <= Threshold ? Replicate(D) ],
                                  RemovePmid.Sy,
                                  [[LyingPmidNode ? CorrectionToPmidManager.So], DownRank(PN)] }

--
<dd>Try to remove Sacrificial data to empty space</ddt>
#####PmidNode::TryToRemoveSacrificial
__PmidNode__ { [PutFailure(RemoveSacrificial(D))], [Store ? Flow_Completed : PutFailure] }

Note: for each removed Sacrificial data, a PutFailure will be sent out
Note - patch: Routing will interpret here that a FailureToStoreData with different data from a ManagedNode indicates a Success on storing the original data and send the error to preceding group as normal, but with different (deterministic message_id) refer to routing issue [#423](https://github.com/maidsafe/routing/issues/423)

--
<dd>Description: Get D from TempStore or network, then PutRequest(D).</ddt>
#####DataManager::Replicate
__DataManager__ ([!TempStoreHas(D) ? NetworkGet(D)])(PutRequest.So(D))
