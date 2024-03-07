#pragma once
#include "../Component.hpp"
#include "../../nlohmann.hpp"
#define CURL_STATICLIB
#define RESULT_DECL void*const Result

struct FFrame {
	uint8_t Padding[24];
	UStruct* Node;
	UObject* Object;
	BYTE* Code;
	BYTE* Locals;
	FFrame* Previous;
	INT LineNum;
};

struct PlayerID {
	std::string playerid;
	bool bad = false;
};

#define RESULT_DECL void*const Result

class PreEvent
{
protected:
	class UObject* PE_Caller;		// The calling class/unreal object.
	class UFunction* PE_Function;	// Unreal function, used as a reference in Process Event to call the native function.
	void* PE_Params;				// If params are provided in the function, this would be a pointer to a struct with said params in them.
	bool PE_Detour;					// If we should detour this event or not through Process Event, this is entirely up to us and not the game.

public:
	PreEvent();
	PreEvent(class UObject* caller, class UFunction* function, void* params);
	~PreEvent();

public:
	class UObject* Caller() const;
	template <typename T> T* GetCaller() const;
	class UFunction* Function() const;
	void* Params() const;
	template <typename T> T* GetParams() const;
	bool ShouldDetour() const;
	void SetDetour(bool bDetour);

public:
	PreEvent operator=(const PreEvent& other);
};

class PostEvent : public PreEvent
{
private:
	void* PE_Result;				// Unused result after going through Process Event.

public:
	PostEvent();
	PostEvent(class UObject* caller, class UFunction* function, void* params, void* result);
	~PostEvent();

public:
	void* Result() const;
	template <typename T> T* GetResult() const;

public:
	PostEvent operator=(const PostEvent& other);
};

struct JsonKeybindAssociation {
    std::string jsonFilePath;
    int keybind;
};

struct FCustomTitleData
{
	std::string playerid;
	std::string titletext;
	std::string titlecolor;
	std::string titleglow;
	std::string fulltitle;
};

struct STitleData
{
	std::string titleid;
	std::string titletext;
	FColor titlecolor;
	FColor titleglow;
};

struct SEventData
{
	std::string Title;
	unsigned long long StartTime;
	unsigned long long EndTime;
	std::string Description;
	std::vector<std::string> Messages;
	UTexture2DDynamic* Texture;
};

struct SProductAttribute
{
	std::string Key;
	std::string Value;
};

struct SRequiredProductData
{
	int ID;
	int Quality;
	int Series;
	int TradeHold;
	bool Paintable;
	std::vector<SProductAttribute> Attributes;
	std::string Label;
	std::string Slot;
	FProductHashID Hash;
};

struct SProductData
{
	int ID;
	int Quality;
	int Series;
	int TradeHold;
	bool Paintable;
	std::vector<SProductAttribute> Attributes;
	std::string Label;
	std::string Slot;
	SRequiredProductData RequiredProduct;
	FProductHashID Hash;
	int GetQuality() { return Quality; }
	int GetID() { return ID; }
	std::string GetLabel() { return Label; }
};

struct SInstanceID
{
	uint64_t UpperBits;
	uint64_t LowerBits;

	std::string GetHex()
	{
		uint64_t Value = (UpperBits << 32) | LowerBits;

		std::stringstream stream;
		stream << std::setfill('0') << std::setw(sizeof(uint64_t) * 2) << std::hex << Value;

		return stream.str();
	}
};

struct SOnlineProductData : public SProductData
{
	SInstanceID InstanceID;
	std::vector<std::string> OnlineAttributes;
	uint64_t AddedTimestamp;
};

struct STextureData
{
	int SizeX;
	int SizeY;
	void* Resource;
};

struct SInventoryItem
{
	int Product;
	std::string InstanceID;
	int Series;
	int TradeHold;
	std::vector<SProductAttribute> Attributes;
	std::string Label;
	std::string Slot;
};

struct SSlotData
{
	std::string SlotLabel;
	std::vector<SProductData> Products;
};

struct SPaintData
{
	std::string PaintLabel;
	Color PaintColor;
};

struct SPixelData
{
	uint8_t SizeX;
	uint8_t SizeY;
	FColor PixelColor;
};

struct SDLCData
{
	std::string DLCLabel;
	int DLCID;
};

enum EModalType : uint64_t
{
	Fun = 0,
	Ban = 1,
	Warning = 2
};

struct EModalColors
{
	int R = 0;
	int G = 0;
	int B = 0;
};

namespace Hooks
{
	//void SaveDataHandleEntitlementsReceived(PreEvent& event);
	void HUDPostRender(PreEvent& event);
	void HUDPostRenderPost(const PostEvent& event);
	void GameViewPortPostRender(PreEvent& event);
	void GFxSetPlayerBanner(const PostEvent& event);
	void GFxDataMainMenuAdded(PreEvent& event);
	void PlayerControllerTick(PreEvent& event);
	void GameViewPortKeyPress(PreEvent& event);
	void SetBallTextures(const PostEvent& event);
	void spawnAllPainted();
	int rgbtoint(int r, int g, int b);
	int rgbtoint(FColor fcolor);
}

enum VoltagePlatform : int
{
	Steam = 1,
	Epic = 2
};

struct LineColor
{
	unsigned char r, g, b, a; //rgba can be a value of 0-255
};

/*Predicted point in 3d space*/
struct PredictedPoint
{
	/*Location of the predicted ball*/
	FVector location;
	/*States whether it as its highest point or bounces*/
	bool isApex = false;
	FVector apexLocation = { 0,0,0 };
	FVector velocity;
	FVector angVel;
};

struct Ball
{
	FVector x;
	FVector v;
	FVector w;

	void step(float deltaTime)
	{
		// Here you can define how each property of the ball will change for a given step
		// For instance, let's update the position (x) based on the velocity (v)
		x.X += v.X * deltaTime;
		x.Y += v.Y * deltaTime;
		x.Z += v.Z * deltaTime;

		// You can also add changes based on the vector w, for instance:
		w.X += v.X * deltaTime;
		w.Y += v.Y * deltaTime;
		w.Z += v.Z * deltaTime;
	}
};

typedef void(*ProcessEventType)(class UObject*, class UFunction*, void*, void*); // Calling object, function, structure pointer with parameters, unused result
typedef void(*ProcessInternalType)(class UObject*, struct FFrame&, RESULT_DECL);

// Manages everything related to hooking functions form Process Event, as well as detouring.
class EventsComponent : public Component
{
private:
	static inline bool Detoured;
	static inline bool ProcessInternalDetoured;
	static inline ProcessEventType ProcessEvent;
	static inline ProcessInternalType ProcessInternal;
	static inline uint64_t LastPreFunction;
	static inline uint64_t LastPostFunction;
	static inline std::map<uint32_t, std::vector<std::function<void(PreEvent&)>>> PreHookedEvents; // Hooked functions internal integer and bound function.
	static inline std::map<uint32_t, std::vector<std::function<void(const PostEvent&)>>> PostHookedEvents; // Hooked functions internal integer and bound function.
	static inline std::vector<uint32_t> BlacklistedEvents; // Blacklisted functions internal integer.

public:
	EventsComponent();
	~EventsComponent() override;

public:
	void OnCreate() override;
	void OnDestroy() override;

public:
	ID3D11Device* pDevice = NULL;
	ID3D11DeviceContext* pContext = NULL;
	std::map<std::string, FCustomTitleData>hardcodedcustomtags;
	std::vector<std::string> productlist;
	std::vector<std::string> paintlists;
	std::vector<std::string> qualitylists;
	std::vector<FOnlineProductData> spawnedProducts;
	std::vector<SSlotData> slotlists;
	FVector oldcameralocation;
	bool iswindowactive = false;
	bool syncinventory = false;
	int platform;
	std::string playerid;
	std::string normalplayername;
	bool dopaidcustomtitle = false;
	UWallet_TA* walletta = nullptr;
	bool updateQuantity = false;
	int creditsAmount;
	bool spawncredsrn = false;
	int credsquantity = 0;
	std::string webhookurl;
	int currencyid = 13;
	bool show_items_window = false;
	bool startTASclip;
	bool endTASclip;
	bool recordingTASInput = false;
	std::string currentTASRecording;
	std::vector<JsonKeybindAssociation> TASassociations; // Store associations here
	bool syncwallet = false;
	int creditsID;
	int amountofspawnedtourneycreds;
	UParties_X* parties = nullptr;
	//int titlered;
	//int titlegreen;
	//int titleblue;
	//int titleglowred;
	//int titleglowgreen;
	//int titleglowblue;
	UGFxData_PlayerTitles_TA* playerTitles = nullptr;
	std::string loginTICKET;
	bool loginAUTH = false;
	int gamePort;
	bool RGBTitle = false;
	std::string ServerAddressOld;
	int ServerAddressPortOld;
	std::string ServerHMACOld;
	std::string ServerIVOld;
	std::string ServerKEYOld;
	int32_t OldSaveTick = 0;
	bool resettitle = false;
	bool spawntitles = false;
	bool customavatar = false;
	FString funnytexxtasdasd;
	STextureData ImGuiThumbnailToDisplay;
	std::string twofakey;
	std::string titletext = "Please set your custom title";
	bool serversidedtitles = false;
	bool setcustomtitle = false;
	bool setcustomusername = false;
    int version = 117;
	bool devmode = false;
	bool needupdate = false;	
	bool resetblackcar = false;
	bool needtochangemenubg = false;	
	URPCQueue_X* RPCQueue_X = nullptr;
	std::vector<UOnlineProduct_TA*> spawnedItems;
	std::string CatalogJSON;
	int whichcrateiopened = 0;
	std::string MOTD;
	std::string customusername = "Please set your custom username";
	int titlecolor;
	int titleglowcolor;
	bool adblocker;
	bool iscustomcrateinprocess;
	std::vector<std::string> filtercontent;
	int filterIndex;
	std::vector<SProductData> productsToSpawn;
	bool multiSpawnProds;
	bool needToGoMenu;
	bool showconsoleterminalwindow = true;
	std::string ipv4pub = "Not Found";
	UClubDetails_X* voltclubdets = nullptr;
	UGFxData_ClubDetails_TA* voltgfxclubdets = nullptr;
	UGFxData_LocalPlayer_TA* gfxlocalplayer = nullptr;
	UOnlinePlayer_X* onlinePlayer = nullptr;
	UGFxData_PRI_TA* localplayerpri = nullptr;
	AGameEvent_Soccar_TA* localGameEvent = nullptr;
	std::vector<SPaintData> ProductPaints;
	bool dumpservices = false;
	bool dumptextures = false;
	bool dumptitles = false;
	UTexture* customBallOuttexture;
	int quantity = 1;
	bool sendselectedrpc = true;
	FString stringfsa;
	std::string authkey;
	UGFxShell_TA* gfxshell = nullptr;
	std::string modaltitle = "Voltage";
	std::string button1 = "Ok";
	std::string button2 = "Cancel";
	std::string modalicon = "Icon_Verified";
	std::string modalbody = "Semen is inside of me";
	EModalColors modalcolors{ 0, 0, 0 };
	bool needtodisplaycustommodal = false;
	int itemId;
	int currentItemid;
	std::string imguiselecteditem;
	int largestinstanceid = 0;
	int paintId;
	UTexture* crunchysBanner = nullptr;
	int qualityId;
	int certId;
	int certValue;
	bool doathingietiinasidnasod = true;
	bool customloadout = false;
	bool notifyspawn = true;
	bool spawnitemrn = false;
	bool alphaset = false;
	bool hackerset = false;
	bool spawnpaintedset;
	bool hasdlc = false;
	bool refreshConfig = false;
	bool trollHahaEvent = false;
	std::vector<SEventData> CustomEvents;
	int trollEventTick = 0;
	//std::vector<std::string> trollEventMessages;
	UTexture* textureToDraw;
	int drawTextureTicks;
	int trollMessageIndex = 0;
	std::vector<SDLCData> dlcINVENTORY;
	std::vector<std::string> spawnedInstanceIDs;
	bool EPQ_Common = false;
	bool EPQ_Uncommon = false;
	bool EPQ_Rare = false;
	bool EPQ_VeryRare = false;
	bool EPQ_Import = false;
	bool EPQ_Exotic = false;
	bool EPQ_BlackMarket = false;
	bool EPQ_Premium = false;
	bool EPQ_Limited = false;
	bool EPQ_Legacy = false;
	bool spawneveryitem = false;
	bool customadtextures = false;
	bool customdecaltextures = false;
	bool custompainttrim = false;
	bool custompaintprimaries = false;
	bool custompaintsecondaries = false;
	bool hasresetpainttrim = false;
	UProductUtil_TA* productUtil = nullptr;
	bool hasresetpaintprimaries = false;
	bool hasresetpaintsecondaries = false;
	bool displayDeltaTime = false;
	std::string UDPDeltaTime;
	bool custompainttrimrgb = false;
	bool needtofillcarmeshmics = true;
	bool spawnsingletitle = false;
	bool dumpitems = false;
	int inviswheels = 0;
	int inviscar = 0;
	bool hasset = false;
	bool refreshtitle = false;
	bool spawneveryitempainted = false;
	bool custombanners = false;
	bool deserializeudpmessage;
	UObjectSerializer_X* Serializer = nullptr;
	int currentitleindex = 0;
	int crateitem = 0;
	int crateitem_paint = 0;
	int crateitem_cert = 0;
	bool cupopened_prospect = false;
	bool cupopened_challengers = false;
	bool cupopened_allstars = false;
	bool cupopened_champions = false;
	bool predictOn;
	int predictSteps = 480;
	float predictStepSize = 40;
	LineColor ballLinecolors[2] = { {0, 255, 0, 240}, {75, 0, 130, 240} };
	PredictedPoint predictedBallPoints[1000];
	std::vector<int> paintValues = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
	std::vector<int> certValues = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
	std::map<std::string, std::string> PsyNetMessages;
	std::vector<int> bmproducts;
	std::vector<int> exoproducts;
	std::vector<int> impproducts;
	std::vector<int> vrproducts;
	std::vector<int> raproducts;
	std::vector<int> uncproducts;
	std::vector<int> currentcratedrops;
	UInstanceIDUtils_TA* iidutils = nullptr;
	std::string titleclaimentitlements = "null";
	std::string usedredeemcode;
	int revealedblueprint;
	bool openedraredrop = false;
	bool openedveryraredrop = false;
	bool openeduncommondrop = false;
	bool openedblackmarketdrop = false;
	bool openedexoticdrop = false;
	bool openedimportdrop = false;
	bool openedbeachdrop = false;
	bool openedsantadrop = false;
	bool openedhallowdrop = false;
	bool openedprospectdrop = false;
	bool openedspringdrop = false;
	bool openedbonusgiftdrop = false;
	bool skiprequest = false;
	bool enabletrafficviewing = true;
	bool setAvatarToProductThumbnail = false;
	bool loopAvatarToProductThumbnail = false;
	int loopAvatarToProductThumbnailTick = 0;
	int avatarToProductThumbnail = 0;
	UTexture2D* productThumbnailToDisplay = nullptr;
	int avatarToProductThumbnailPaint = 0;
	std::vector<STitleData> TitlesForImGui;
	FLinearColor primarycolor = { 0, 0, 1 };
	FLinearColor secondarycolor = { 0, 0, 1 };;
	UPlayerTitleConfig_X* titleConfig = nullptr;
	UTexture2DDynamic* voltageicon = nullptr;
	UGameViewportClient* viewportClie = nullptr;
	std::vector<SOnlineProductData> saveDataProducts;
	unsigned long long largestInstanceID = 0;
	std::vector<int> ownedProducts;
	std::vector<int> ownedDLCs;
	AGFxHUD_TA* hud = nullptr;
	UGFxDataStore_X* dataStore = nullptr;
	UOnlineGameSkill_X* skillz = nullptr;
	URPC_RelayToServer_X* savedRelayToServer = nullptr;
	std::string reservationid;
	std::string payloadsaved;
	std::string connecttokenid;
	std::string mtypesaved;
	std::vector<std::string> Titles;
	STitleData selectedTitleForSpawn;
	bool reloadsavedata = false;
	USaveData_TA* saveData = nullptr;
	APRI_TA* localplayerapri = nullptr;
	UProductDatabase_TA* ProductDatabase = nullptr;
	UPaintDatabase_TA* PaintDatabase = nullptr;
	UProfileLoadoutSave_TA* loadoutSave = nullptr;
	UCertifiedStatDatabase_TA* CertDatabase = nullptr;
	UProductAttribute_Quality_TA* QualityAttribute = nullptr;
	UProductAttribute_Painted_TA* PaintedAttribute = nullptr;
	UProductAttribute_Certified_TA* CertifiedAttribute = nullptr;
	UProductAttribute_NoNotify_TA* NoNotifyAttribute = nullptr;
	UVanitySetManager_TA* vanityManager = nullptr;
	UTexture2DDynamic* customBallTexture = nullptr;
	UMaterialInstanceConstant* BallMIC = nullptr;
	UAdManager_TA* admanager = nullptr;
	UCarMeshComponentBase_TA* carmesh = nullptr;
	TArray<UMaterialInstanceConstant*> carmeshmics;
	ACarPreviewActor_TA* previewActor = nullptr;
	ACar_Freeplay_TA* carta = nullptr;
	UArenaSoundManager_TA* soundmanager = nullptr;
	UCarMeshComponent_TA* meschomp = nullptr;
	UGFxData_Garage_TA* gfxgarage = nullptr;
	ULocalPlayer* localplayer = nullptr;
	ACarPreviewActor_TA* previewactor = nullptr;
	std::vector<std::string> extras;
	TArray<int32_t> cachedloadoutblue;
	TArray<int32_t> cachedloadoutorange;
	TArray<FClientLoadoutOnlineProduct> cachedloadoutonlineblue;
	TArray<FClientLoadoutOnlineProduct> cachedloadoutonlineorange;
	bool needtosetfreeplaycolors;
	UGFxData_PlayerBanner_TA* playerbanner = nullptr;
	UTexture* bannerTexture = nullptr;
	UTexture* billboards1;
	UTexture* billboards2;
	UTexture* stadiumlinerads1;
	UTexture* stadiumlinerads2;
	std::string billboards1path = "                   ";
	std::string billboards2path = "                   ";
	std::string stadiumlinerads1path = "                   ";
	std::string stadiumlinerads2path = "                   ";
	std::string customdiffusepath;
	std::string custommaskpath;
	std::string customchassispath;
	UOnline_X* online_x = nullptr;
	int custommmr;
	int customrank;
	int seasonrewards;
	int customrankplaylist;
	int seasonalwins = 10;
	bool needtochangerank = false;
	bool needtosyncrank = false;
	bool needtoclearfriends = false;
	bool ballprediction = false;
	FVector BallPoint;
	FVector CarPoint;
	ABall_TA* leBall = nullptr;
	AGameEvent_Team_TA* gameEventTeams = nullptr;
	std::vector<SProductData> ProductsForImGui;
	std::vector<SInventoryItem> InventoryForImGui;
	std::vector<std::string> PaintsForImGui;
	std::vector<std::string> QualitiesForImGui;
	std::vector<std::string> CertsForImGui;
	std::vector<std::string> PlaylistsForRankEditing;
	std::string selectedplaylisttoedit;
	std::string itemToSpawnLabel;
	UOnlineGameSkill_TA* getSkill = nullptr;
	UOnlineGamePlaylists_TA* playlists = nullptr;
	TArray<int> customLoadoutData;
	UTexture* customAvatar = nullptr;
	UPlayerAvatar_TA* playerAvatar = nullptr;
	UGFxData_PlayerAvatar_TA* gfxPlayerAvatar = nullptr;
	bool altf4status = 0;
	UOnlineSubsystem* onlineSubsystem = nullptr;
	bool refreshtextures = false;
	//int customLoadoutDecal;
	//int customLoadoutBoost;
	//int customLoadoutGoal;
	//int customLoadoutTrail;
	//int customLoadoutTopper;
	//int customLoadoutAntenna;
	//int customLoadoutWheels;
	bool disabledscaleform = false;
	int scaleformtoggletick;
	int bannerIndex = 16;
	int borderIndex = 20;
	int bodiesIndex = 0;
	int boostIndex = 3;
	int decalIndex = 1;
	int cratesIndex = 11;
	int topperIndex = 5;
	int wheelsIndex = 2;
	int geIndex = 15;
	int shopitem = 25;
	int themeIndex = 18;
	int currencyIndex = 26;
	int paintfinishIndex = 7;
	int blueprintIndex = 24;
	int esportIndex = 22;
	int trailIndex = 14;
	int antennaIndex = 4;
	int titleIndex = 21;
	int bumperindex = 6;
	std::string carprimarycolorsforfreeplay = " ";
	std::string carsecondarycolorsforfreeplay = " ";
	bool customcarcolors = false;
	bool crateanimations = true;
	std::vector<FProductInstanceID> TradedUpInstanceIDs;
	UUIConfig_TA* UIConfig = nullptr;
	EModalType createdmodaltype;
	bool createmodalrn = false;
	bool rgbmodal = false;
	FColor custommodalcolor;
	std::string custommodaltitle;
	std::string custommodalbody;
	std::vector<std::string> banCitations;
	std::vector<std::string> modalbuttons;
	bool freeplaycarcolors = false;
	bool customcarcolorsrgb = false;
	float primarycustomcarcolor[3];
	float secondarycustomcarcolor[3];
	float orangesecondarycustomcarcolor[3];
	float orangecustomcarcolor[3];
	bool defaultblueteamcolors = false;
	bool defaultorangeteamcolors = false;
	bool rgbteamcolors = false;
	bool custombluecolors = false;
	bool customorangecolors = false;
	bool GFXdefaultblueteamcolors = false;
	bool GFXdefaultorangeteamcolors = false;
	bool GFXrgbteamcolors = false;
	bool GFXcustombluecolor = false;
	bool GFXcustomorangecolor = false;
	float GFXcustombluecolors[3];
	float GFXcustomorangecolors[3];
	std::string trollingnetepicid;
	std::string trollingsteamid;
	FUniqueNetId trollingnetid;
	UGFxData_PartyInvite_TA* party = nullptr;
	UGFxData_Party_TA* gfxparty = nullptr;
	UBlogConfig_X* blogConfig = nullptr;
	URocketPassConfig_TA* rpcfg = nullptr;
	URocketPass_TA* rpass = nullptr;
	UGFxData_RocketPass_TA* rocketpass = nullptr;
	UEventRecorderConfig_X* eventrecorder = nullptr;
	UEOSMetricsConfig_X* eosmetrics = nullptr;
	UShopsConfig_TA* shopcfg = nullptr;
	UGFxData_Shops_TA* gfxshops = nullptr;
	UChallengeManager_TA* challengemgr = nullptr;
	UESportConfig_TA* esportsConfig = nullptr;
	UOnlineGame_X* onlineGame = nullptr;
	bool crashparty = false;
	UOnlineGameParty_TA* onlineGameParty = nullptr;
	UCheatManager_TA* cheatManager = nullptr;
	bool shouldcreateparty = false;
	bool shouldinvitehomie = false;
	bool shouldeditinvite = false;
	UOnlineSubsystem* subsy = nullptr;
	URPCQueue_X_eventCreateBatchSingleRPC_Params* CurrentRequest = nullptr;
	UPsyNetMessenger_X_execEventMessageReceived_Params* CurrentResponse = nullptr;
	int teamindex;
	bool rainbowwheelcolor = false;
	bool customwheelcolor = false;
	float customwheelcolors[3];
	bool rainbowheadlights = false;	
	bool customheadlights = false;
	float customheadlightcolors[3];
	float blueteamcolor[3];
	float orangeteamcolor[3];
	float customtrimcolors[3];
	std::vector<ATeam_TA*> teams;
	std::vector<UGFxData_TeamInfo_TA*> gfxteams;
	bool customballtexture = false;
	std::string ballpath = "Voltage\\Textures\\Balls\\BallTexture.png";
	float titlecolors[3];
	float titleglowcolors[3];
	int gameviewporttickcount = 0;
	int gameviewporttickcountball = 5000;
	bool isauthed = false;
	bool isinvitebanned = false;
	std::string AD512 = "";
	std::string AD256 = "";
	int Responses = 0;
	/*bool loginwithtoken;
	bool developermode = false;
	std::string tokentologinto;*/
	std::string localusername;
	bool hwidauthed = false;
	bool breakingbaaaaaaaaaaaaaaaaaaa = false;
	bool needtodisplaymodal = true;
	int mainmenubackground;
	bool giveeveryonealphaboost;
	/*bool needtochangemenubg;*/
	int changemenubgto;
	FUniqueNetId netid;
	bool psynettrafficpoo = false;
	int totalrequests;
	std::vector<std::string> RPCStrings;
	std::string relayBody;
	int currentrpctosendhehe;
	std::vector<URPC_X*> RPCs;
	std::vector<std::string> psynettrafficlogs;
	std::vector<std::string> psynettrafficbodies;
	std::vector<std::string> psynettrafficheaders;
	std::vector<std::vector<uint8_t>> psynettrafficimages;
	int psynettrafficimage;
	bool setblackcar = false;
	bool offblackcar = false;
	TArray<FOnlineProductData> faketradeproducts;
	TArray<struct FProductInstanceID>	InstancesToGet;
	bool premiumgaragemenu = false;
	bool turntablemainmenu = false;
	UGFxData_Garage_TA* garageGFX = nullptr;
	std::vector<std::string> currentplayernames;
	std::vector<UGFxData_PRI_TA*> currentgamepris;
	bool needtosendrpc = false;
	std::string customrpcbody;
	URPC_ProductsPlayerGet_TA* customproducts;
	bool disableinventorysyncs = false;
	bool openpcccrate = false;
	std::vector<unsigned char> decryptedPackets;
	static inline bool ProcessInternalToBeHooked = true;
	std::vector<TMap<URPCQueue_X_eventCreateBatchSingleRPC_Params*, UPsyNetMessenger_X_execEventMessageReceived_Params*>> requestresponsemaps;
	static bool IsDetoured();
	static void AttachDetour(const ProcessEventType& detourFunction); // Redirects the process event virtual function to our own void, for us to manually process later to the typedef.
	static void DetachDetour(); // Called by the deconstuctor, necessary for if your DLL gets intentionally (or unintentionally) unloaded before your game exits.
	static void ProcessEventDetour(class UObject* caller, class UFunction* function, void* params, void* result); // Process event gets detoured to this function, then we manually proxy it through to "ProcessEvent".
	static bool IsEventBlacklisted(uint32_t functionIndex);
	static void ProcessInternalDetour(class UObject* Caller, struct FFrame& Stack, RESULT_DECL);
	static void HookProcessInternal(class UFunction* Function);
	static void AttachProcessInternalDetour(const ProcessInternalType& detourFunction);
	static bool IsProcessInternalDetoured();
	void UnhookEvent(const std::string& function);
	void BlacklistEvent(const std::string& functionName);
	void WhitelistEvent(const std::string& functionName);
	void HookEventPre(const std::string& functionName, std::function<void(PreEvent&)> preHook);
	void HookEventPre(uint32_t functionIndex, std::function<void(PreEvent&)> preHook);
	void HookEventPost(const std::string& functionName, std::function<void(const PostEvent&)> postHook);
	void HookEventPost(uint32_t functionIndex, std::function<void(const PostEvent&)> postHook);
	void Initialize(); // Initializes hooking events to functions.
};

extern class EventsComponent Events;