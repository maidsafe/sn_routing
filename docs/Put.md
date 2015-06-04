###Put(D)
_MaidNode_ =>> |__MaidManager__ [Allow ? So : PutFailure]  *->> |__DataManager__  [Exist(D) ? PutResponse : {([AddTempStore(D), Put.Sy])(So), PutResponse}] *->> |__PmidManager__ {So, Put.Sy, PutResponse} *-> |_PmidNode_ [!Store ? PutFailure]

--
#####MaidManager::PutFailure
__MaidManager__ *-> |_MaidNode_ 

--
#####DataManager::PutResponse
__DataManager__ *->> |__MaidManager__ [So, Put.Sy] *-> |_MaidNode_ 

--
<dd>Description: Get D from TempStore or network, then PutRequest(D).</ddt>
#####DataManager::Replicate
__DataManager__ ([!TempStoreHas(D) ? NetworkGet(D)])(PutRequest.So(D))

--
#####PmidManager::PutResponse
__PmidManager__ *->> |__DataManager__ {[Value.Pmids.Count < Threshold ? Replicate(D) : RemoveTempStore(D)], AddPmid.Sy}

--
#####PmidNode::PutFailure
_PmidNode_ ->> |__PmidManager__ {So, Delete.Sy} *->> |__DataManager__ {[Value.Pmids.Count <= Threshold ? Replicate(D) : RemoveTempStore(D)], RemovePmid.Sy, [[LyingPmidNode ? CorrectionToPmidManager.So], DownRank(PN)]}

