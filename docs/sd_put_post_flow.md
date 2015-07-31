# Workflow for puting structured data to Vault Network
Putting structured data to Vault Network will be the same from client's perspective. The put request, holding the structured data as payload, goes to client's client manager (MaidManager) first who will check whether enough allownance is still available.
Once it is approved, MaidManager will pass the request to the NetworkElementManagers around the data's name.
However, unlike immutable data for which DataManagers will pick up and handle the request, this time another special persona, named as StructuredDataManager, will pick up and handle the request.
StructuredDataManager stores the structured data in it, just like PmidNode taking care of the immutable data.

### Put(SD)
_Client_  =>> |__ClientManager__ (StructuredData))[Allow ? So : PutFailure]
         *->> |__StructuredDataManager__  [Exist(SD) ? Terminate_Flow : Store(SD)]

--
##### MaidManager::PutFailure
__ClientManager__ *-> |_Client_


# Workflow for posting data to Vault Network
In vault network, "posting" means data manipulation, i.e. allows data to be updated by the data owner.
Some assumptions are made here :
    1, The data type is versionable(i.e. manipulatable), currently there is only StructuredData has been defined
    2, The original copy of such data must be put to the network from client first, via MaidManager then to StructuredDataMangager
    3, It is up to the client or client's app to define and parse the data payload of StructuredData, for detailed description, please refer to the documentation of [Unified Structured Data](https://github.com/maidsafe/rfcs/blob/master/active/0000-Unified-structured-data.md)

Client can send post request to network which will be handled by the StructuredDataMangager around the computed name of that structured data.
If the majority of the previous owners of the data proved to be agree with the update, i.e. their valid signatures are prensented in the new version of the copy, StructuredDataMangager will update it, i.e. replace the old copy with the new incoming one.

### Post(SD_name, new_copy)
_Client_  *->> |__StructuredDataManager__  [Exist(SD_name) ? Update(SD_name, newV) : Terminate_Flow]
