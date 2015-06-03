# Workflow for posting data to Vault Network
In vault network, "posting" means data manipulation, i.e. allows data to be updated by the data owner.
Some assumptions are made here :
    1, The data type is versionable(i.e. manipulatable), currently there is only StructuredData has been defined
    2, The original copy of such data must be put to the network from client directly to VersionaHandler
    3, The data copy that new version pointing to has been uploaded to the network following the normal put flow.

Client first send a put request to network with the original copy versionable data (StructuredData).
This will be handled by VersionHandlers directly. No response will be given back.

Client later on can send post request to network which will be handled by the VersionHandlers around the hash name of that versionable data.
If the client proved to be the owner of that versionable data, VersionHandlers will update it.
There will be no response being sent back no matter such update is succeed or fail.

###Put(VD)
_Client_  *->> |__VersionHanlder__  [Exist(VD) ? Terminate_Flow : Register(VD)]

###Post(VD_name, newV)
_Client_  *->> |__VersionHanlder__  [Exist(VD_name) ? Update(VD_name, newV) : Terminate_Flow]

