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
          *->  |_PmidNode_ [Store ? Flow_Completed : Primary? TryToRemoveSacrificial : PutFailure]

Note : when routing_node realise it is acting as ClientManager, handle_put will be called three times to trigger Primary, Backup and Sacrificial copies of data to be stored to network.
Only when Primary is not allowed to be put, then ClientManager will send back a PutFailure to Client

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

--
<dd>Description: Get D from TempStore or network, then PutRequest(D).</ddt>
#####DataManager::Replicate
__DataManager__ ([!TempStoreHas(D) ? NetworkGet(D)])(PutRequest.So(D))






