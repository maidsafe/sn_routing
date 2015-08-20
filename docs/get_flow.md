# Workflow for getting data from Vault Network
Client send get requests to network which will be handled by NAE(DataManager) first.
Attempts to fetch Backup and Sacrificial copies will be carried by client at the same time.
i.e. there will be three get requests fired to network at the same time,
     and DMs around data_name(Hash(data)) for Primary copy, Hash(data_name) for Backup copy,
         and Hash(Hash(data_name)) for Sacrificial copy will be queried at the same time.
When DMs receive the get request, it will forward the request to all the pmid_nodes in the data record's holders list.
When pmid_node receive the get request, if it has the data, it will reply with the data (routing ensures the response will be sent to the Client directly).
TODO: it is optional the replied data being sent to DMs as well so that they can carry out data verification.
If there is no data stored, it will reply with an error (routing ensures the failure response being sent back to the DMs, which will update its record to remove this pmid_node as holder.)


### Get(N)
_Client_  *->> |__DataManager__  (Primary, Backup, Sacrificial) [Exist(name) ? So : Terminate_Flow]
          *->  |_PmidNode_ [Has(name) ? Reply(data) : Terminate_Flow]

Note : name is N which is Hash(D) for Primary copy, is Hash(N) for Backup copy and is Hash(Hash(N)) for Sacrificial copy
       data is Primary or Backup or Sacrificial copy


--
##### PmidNode::PutFailure
_PmidNode_ ->> |__DataManager__ { [Value.Pmids.Count <= Threshold ? Replicate(D) ],
                                  RemovePmid.Sy,
                                  [[LyingPmidNode ? CorrectionToPmidManager.So], DownRank(PN)] }


--
<dd>Description: Get D from TempStore or network, then PutRequest(D).</ddt>
##### DataManager::Replicate
__DataManager__ ([!TempStoreHas(D) ? NetworkGet(D)])(PutRequest.So(D))
