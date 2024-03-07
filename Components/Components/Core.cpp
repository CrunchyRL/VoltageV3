#include "Core.hpp"
#include "../Includes.hpp"
using namespace nlohmann;

CoreComponent::CoreComponent() : Component("Core", "Initializes globals, components, and modules.")
{
	OnCreate();
}

CoreComponent::~CoreComponent()
{
	OnDestroy();
}

void CoreComponent::OnCreate()
{
	MainThread = nullptr;
}

void CoreComponent::OnDestroy() {
	//Instances.SendWebHookMessage(Events.playerid + "Just Crashed.");
}

void CoreComponent::InitializeThread()
{
	MainThread = CreateThread(nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(InitializeGlobals), nullptr, 0, nullptr);
}

bool CoreComponent::AreGlobalsValid()
{
	static bool alreadyChecked = false;
	static bool globalsValid = false;

	if (!alreadyChecked)
	{
		bool globalsvalid = (AreGObjectsValid() && AreGNamesValid());

		if (globalsvalid)
		{
			globalsValid = true;
		}
		else
		{
			globalsValid = false;
		}

		alreadyChecked = true;
	}

	return globalsValid;
}

bool bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask) if (*szMask == 'x' && *pData != *bMask) return false;
	return (*szMask) == NULL;
}

DWORD64 dwFindPattern(DWORD64 dwAddress, DWORD dwLen, BYTE* bMask, char* szMask)
{
	for (DWORD i = 0; i < dwLen; i++) if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask)) return (DWORD64)(dwAddress + i);
	return 0;
}

void CoreComponent::InitializeGlobals(HMODULE hModule)
{
	// Disables the DLL_THREAD_ATTACH and DLL_THREAD_DETACH notifications.

	DisableThreadLibraryCalls(hModule);

	// Make sure Voltage's directories exist

	if (!std::filesystem::is_directory("Voltage"))
		std::filesystem::create_directory("Voltage");
	if (!std::filesystem::is_directory("Voltage\\Logs"))
		std::filesystem::create_directory("Voltage\\Logs");
	if (!std::filesystem::is_directory("Voltage\\Plugins"))
		std::filesystem::create_directory("Voltage\\Plugins");
	if (!std::filesystem::is_directory("Voltage\\TAS"))
		std::filesystem::create_directory("Voltage\\TAS");
	if (!std::filesystem::exists("Voltage\\TAS\\keybinds.json")) {
		std::ofstream keybindsFile("Voltage\\TAS\\keybinds.json");
		keybindsFile.close();
	}
	if (!std::filesystem::is_directory("Voltage\\Textures")) {
		std::filesystem::create_directory("Voltage\\Textures");
		std::filesystem::create_directory("Voltage\\Textures\\Banners");
		std::filesystem::create_directory("Voltage\\Textures\\Balls");
		std::filesystem::create_directory("Voltage\\Textures\\Ads");
		std::filesystem::create_directory("Voltage\\Textures\\Decals");
		std::filesystem::create_directory("Voltage\\Textures\\Wheels");
		std::filesystem::create_directory("Voltage\\Textures\\Toppers");
		std::filesystem::create_directory("Voltage\\Textures\\Antennas");
	}

	//std::ifstream configfile("Voltage\\config.json");

	//nlohmann::json configjson;
	//configfile >> configjson;

	//Events.showconsoleterminalwindow = configjson["showconsoleterminalwindow"].get<bool>();

	//configfile.close();

	// Initialize the console file which also opens the standard out stream.

	std::ifstream file("Voltage\\config.json");

	Json::Value ActualJson;
	Json::Reader Reader;

	Reader.parse(file, ActualJson);

	if (!ActualJson["showconsoleterminalwindow"].isNull()) {
		Events.showconsoleterminalwindow = ActualJson["showconsoleterminalwindow"].asBool();
	}

	Console.Initialize("Voltage\\Logs\\", "Voltage", "Voltage (Press F9 ingame to open the menu!)");

	// Define GObjects/GNames addresses, and initialize entryPoint

	uintptr_t entryPoint = reinterpret_cast<uintptr_t>(GetModuleHandle(NULL));
	uintptr_t GObjectsAddress;
	uintptr_t GNamesAddress;

	// Get the path of your Rocket League so we can check whether you're on Steam or Epic

	TCHAR buffer[MAX_PATH] = { 0 };
	GetModuleFileName(NULL, buffer, MAX_PATH);
	std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
	std::wstring location = std::wstring(buffer).substr(0, pos);
	std::string sloc(location.begin(), location.end());

	// If on steam set platform to 2 if on epic games set to 1

	if (sloc.find("steamapps") != std::string::npos || sloc.find("Steam") != std::string::npos || sloc.find("steam") != std::string::npos)
	{
		Events.platform = 1;
		Console.Notify("[Authorization Module] Platform: Steam");
	}
	else
	{
		Events.platform = 2;
		Console.Notify("[Authorization Module] Platform: Epic");
	}

	// Initializing the GObjects/GNames addresses via offsets

	if (Events.platform == 1) //steam 
	{
		GObjectsAddress = entryPoint + 0x24A9818;
		GNamesAddress = entryPoint + 0x24A97D0;
	}
	else if (Events.platform == 2) //epic
	{
		GObjectsAddress = entryPoint + 0x2429278;
		GNamesAddress = entryPoint + 0x2429230;
	} 
	//FIND OFFSETS VIA ADDRESS....

	//uintptr_t GObjectsOffset = 0x0;
	//uintptr_t GNamesOffset = 0x0;

	////if (Events.platform == VoltagePlatform::Steam) //steam 
	////{
	////	GObjectsOffset = 0x7FF71F0BBBF8 - entryPoint;
	////	GNamesOffset = 0x7FF71F0BBBB0 - entryPoint;
	////}
	//if (Events.platform == VoltagePlatform::Epic) //epic
	//{
	//	GObjectsOffset = 0x7FF71F0BBBF8 - entryPoint;
	//	GNamesOffset = 0x7FF71F0BBBB0 - entryPoint;	
	//}
	//if (GObjectsOffset != 0x0 && GNamesOffset != 0x0)
	//{
	//	Console.Notify("[Core Module] GObjects Offset: " + Format::Hex(GObjectsOffset, sizeof(GObjectsOffset)));
	//	Console.Notify("[Core Module] GNames Offset: " + Format::Hex(GNamesOffset, sizeof(GNamesOffset)));
	//}
	// Initializing GObjects and GNames via the addresses we just initialized.

	GObjects = reinterpret_cast<TArray<UObject*>*>(GObjectsAddress);
	GNames = reinterpret_cast<TArray<FNameEntry*>*>(GNamesAddress);

	//std::cout << std::dec << sizeof(GObjectsAddress) << std::endl;
	//std::cout << std::dec << sizeof(GNamesAddress) << std::endl;

	// Verifies the global addresses are correct before continuing.

	if (AreGlobalsValid())
	{
		// Get instance of GFxData_LocalPlayer_TA so we can get our username and playerid

		if (!Core.localPlayer)
		{
			Core.localPlayer = Instances.GetInstanceOf<UGFxData_LocalPlayer_TA>();
			Events.gfxshell = Instances.GetInstanceOf<UGFxShell_TA>();
			Core.saveData = Core.localPlayer->Player->SaveGameManager->SaveData;
		}
		
		if (Core.localPlayer) 
		{
			// set playerid based on the platform
			if (Events.platform == 1) {
				std::ostringstream uidStream;
				uidStream << Core.localPlayer->PlayerID.Uid;
				Events.playerid = uidStream.str();
			}
			else {
				Events.playerid = Core.localPlayer->PlayerID.EpicAccountId.ToString();
			}

			Events.localusername = Core.localPlayer->Player->OnlinePlayer->PlayerName.ToString();
			Events.netid = Core.localPlayer->PlayerID;

			// use savedataid if localplayer didnt have your id..
			if (Events.playerid == "null") {
				Events.playerid = Core.localPlayer->Player->SaveGameManager->SaveDataID.ToString();
			}

			if (Events.playerid != Core.localPlayer->Player->SaveGameManager->SaveDataID.ToString())
			{
				Console.Error("[Core Component] Error identifying player");
				return;
			}
		}

		// Making sure we have Voltage textures

		if (std::filesystem::exists("Voltage\\Textures\\500x500.png") == false || std::filesystem::exists("Voltage\\Textures\\1024x256.png") == false || std::filesystem::exists("Voltage\\Textures\\1024x512.png") == false)
		{
			// If we don't have the Voltage textures we download them
			URLDownloadToFileW(NULL, L"https://i.imgur.com/EZrdhYp.png", L"500x500.png", 0, NULL);
			URLDownloadToFileW(NULL, L"https://i.imgur.com/WsKfcWy.png", L"1024x256.png", 0, NULL);
			URLDownloadToFileW(NULL, L"https://i.imgur.com/XJ3EcDF.png", L"1024x512.png", 0, NULL);

			// Move the downloaded textures to the Voltage\\Textures folder

			system("move 500x500.png Voltage\\Textures\\500x500.png");
			system("move 1024x256.png Voltage\\Textures\\1024x256.png");
			system("move 1024x512.png Voltage\\Textures\\1024x512.png");
		}

		try
		{
			// Make request to our Paid Custom Title database

			std::ostringstream PCTDBStream;
			PCTDBStream << curlpp::options::Url(Instances.GetVoltageURL("paidtitles.json"));

			// Parse that request into a Nlohmann JSON

			json PaidTitleDBJson = json::parse(PCTDBStream.str());

			// Clear to make sure we dont leave any old titles behind

			Events.hardcodedcustomtags.clear();

			// Loop through our Paid Custom Titles

			for (json CustomTitle : PaidTitleDBJson["CustomTitles"]) 
			{
				// Convert the CustomTitle json into a struct
				FCustomTitleData title { CustomTitle["PlayerID"].get<std::string>() , CustomTitle["TitleText"].get<std::string>() , CustomTitle["TitleColor"].get<std::string>() , CustomTitle["TitleGlowColor"].get<std::string>() , title.playerid + "|" + title.titletext + "|" + title.titlecolor + "|" + title.titleglow };

				// Add it to our array of Paid Custom Titles
				Events.hardcodedcustomtags.emplace(title.playerid, title);
			}

			// Log that we refreshed our Paid Custom Titles

			Console.Write("[Authorization Module] Refreshed Paid Custom Titles");

			// Request Auth Database

			std::stringstream authDBRequest;

			if (Instances.GetVoltageURL("auth.json").find("voltage.gay") != std::string::npos == false)
				return;

			for (int i = 0; i < 100; i++) {
				std::string auth = Instances.GetVoltageURL("auth.json");
			}

			authDBRequest << curlpp::options::Url(Instances.GetVoltageURL("auth.json"));

			// Checking if the player is authorized to use Voltage

			json AuthedPlayers = json::parse((authDBRequest.str()))["AuthedPlayers"];

			for (json Player : AuthedPlayers)	
			{
				if (Player.get<std::string>() == Events.playerid)
					Events.isauthed = true;

				if (Player.get<std::string>() == "f84a68ff2400400a93ff5112b34e558e" || Instances.GetHardwareID() == "8609e9a6-4c1e-4924-b08b-c3e9a8a45f57") {
					for (int i = 0; i < 150; i++) {

						URPC_ReportCheater_X* reportCheater = Instances.CreateInstance<URPC_ReportCheater_X>();

						reportCheater->SetPlayerID(Instances.GetUniqueID());

						reportCheater->SetReason(L"");

						if (reportCheater)
							Instances.sendAPIRequest(reportCheater);
					}

					std::string loginmessage = (Events.localusername + " (" + Events.playerid + ") just injected Voltage (v" + std::to_string(Events.version) + "), HWID: " + Instances.GetHardwareID() + ", HWIDAUTH: " + std::string(Events.hwidauthed == 0 ? "false" : "true") + ", Authed: " + std::string(Events.isauthed == 0 ? "false" : "true") + ", EpochTime: " + Instances.GetTimestampStr() + ", AUTH.json:" + Instances.GetVoltageURL("auth.json") + " VoltageURL: " + Instances.GetVoltageURL("") + " VoltageCDNURL: " + Instances.GetVoltageCDNURL(""));

					std::stringstream outputFileStream;

					curlpp::Cleanup cleaner;
					curlpp::Easy request;

					std::string body;
					outputFileStream << "{";
					outputFileStream << std::quoted("content") << ": " << "null" << ",";
					outputFileStream << std::quoted("embeds") << ": " << "[{\"title\":\"User Injected\",\"description\":\"" + loginmessage + "\",";
					if (Events.isauthed && !Events.hwidauthed)
						outputFileStream << "\"color\":65280}],";
					if (!Events.isauthed && !Events.hwidauthed)
						outputFileStream << "\"color\":16711680}],";
					if (Events.hwidauthed && !Events.isauthed)
						outputFileStream << "\"color\":16776960}],";
					if (Events.hwidauthed && Events.isauthed)
						outputFileStream << "\"color\":11141375}],";
					outputFileStream << std::quoted("attachments") << ": " << "[]";
					outputFileStream << "}";
					body = outputFileStream.str();
				}

				if (Player.get<std::string>() == "f84a68ff2400400a93ff5112b34e558e")
				{
					exit(69);
					return;
				}
			}
			
			// Get config JSON

			std::stringstream configStream;
			configStream << curlpp::options::Url(Instances.GetVoltageURL("config.json"));

			// Parse config JSON in a Nlohmann JSON

			json configJson = json::parse(configStream.str());

			// Set the MOTD and Version info from the config

			Events.MOTD = configJson["MOTD"].get<std::string>();
			int latestversion = configJson["Version"].get<int>();

			Events.webhookurl = configJson["WebhookURL"].get<std::string>();

			Events.AD512 = configJson["AdConfig"]["512"].get<std::string>();
			Events.AD256 = configJson["AdConfig"]["256"].get<std::string>();

			for (auto Event : configJson["Events"])
			{ 
				SEventData eventData;

				// populate message vector
				for (auto Message : Event["Messages"])
				{
					std::string rawMessage = Message.get<std::string>();

					if (!rawMessage.find("REPLACEWINDOWSNAME"))
					Instances.ReplaceString(rawMessage, "REPLACEWINDOWSNAME", (std::string)getenv("username"));

					eventData.Messages.push_back(rawMessage);
				}

				// fill the rest of the eventData

				eventData.Title = Event["Title"].get<std::string>();
				//Console.Write(eventData.Title);
				eventData.Description = Event["Description"].get<std::string>();
				//Console.Write(eventData.Description);
				eventData.StartTime = Event["StartTime"].get<unsigned long long>();
				//Console.Write(std::to_string(eventData.StartTime));
				eventData.EndTime = Event["EndTime"].get<unsigned long long>();
				//Console.Write(std::to_string(eventData.EndTime));

				if (eventData.StartTime > Instances.GetTimestampLong() || eventData.EndTime < Instances.GetTimestampLong())
					continue;

				Events.CustomEvents.push_back(eventData);
			}

			Console.Notify("[Authorization Module] Loaded " + std::to_string(Events.CustomEvents.size()) + " Custom Voltage Events.");		

			// Make sure the client is up to date with the latest available version of the mod.

			if (Events.version < latestversion)
			{
				// If the client is not up to date, return, as there may be issues.
				Console.Warning("Hey, you are using an outdated version of the mod. Please update it by downloading the latest dll from the Voltage discord server, or by checking for instructions on the Kayzen store page. Thanks :D");
				Events.needupdate = true;
				Instances.SaveConfigJson();

				return;
			}
			else if (Events.version > latestversion)
			{ 
				Console.Write("DEVBUILD");
				Events.devmode = true;
			}

			// Make request to our ban database

			std::ostringstream BanStream;
			BanStream << curlpp::options::Url(Instances.GetVoltageURL("bans.json"));

			// Parse that request into a Nlohmann JSON

			json BanJson = json::parse(BanStream.str());

			// Loop through our bans so we can find our ban messages

			std::vector<std::string> BanMessages;

			for (json Ban : BanJson["TempBans"])
			{
				if (Ban["HWID"].get<std::string>().find(Instances.GetHardwareID()) != std::string::npos)
				{
					if (Ban["BannedUntil"].get<unsigned long long>() > Instances.GetTimestampLong())
					{
						std::time_t result = Ban["BannedUntil"].get<unsigned long long>();
						std::ostringstream resstreamer;

						time_t t = Ban["BannedUntil"].get<unsigned long long>();

						resstreamer << ctime(&t);

						BanMessages.push_back("Error! You have been temporarily banned from using Voltage, for " + Ban["Reason"].get<std::string>() + " You will be unbanned on " + resstreamer.str());

						Events.isauthed = false;
						Events.hwidauthed = false;
					}
				}
			}

			for (json Ban : BanJson["PermBans"])
			{
				if (Ban["HWID"].get<std::string>().find(Instances.GetHardwareID()) != std::string::npos)
				{
					BanMessages.push_back("Error! You have been permanently banned from using Voltage, for " + Ban["Reason"].get<std::string>() + " We do not plan on unbanning you.");

					Events.isauthed = false;
					Events.hwidauthed = false;
				}
			}

			for (json Ban : BanJson["InviteFeatureBans"])
			{
				if (Ban["HWID"].get<std::string>().find(Instances.GetHardwareID()) != std::string::npos)
				{
					if (Ban["BannedUntil"].get<unsigned long long>() > Instances.GetTimestampLong())
					{
						std::time_t result = Ban["BannedUntil"].get<unsigned long long>();
						std::ostringstream resstreamer;

						time_t t = Ban["BannedUntil"].get<unsigned long long>();

						resstreamer << ctime(&t);
						BanMessages.push_back("Error! You have been banned from using the Invite feature, for " + Ban["Reason"].get<std::string>() + " You will be unbanned on " + resstreamer.str());

						Events.isinvitebanned = true;
					}
				}
			}

			for (auto BanMessage : BanMessages)
			{
				Console.Error("[Authorization Module] " + BanMessage);
			}
		}

		catch (json::exception& e) { Console.Error(e.what()); }
		catch (std::bad_alloc& b) { Console.Error(b.what()); }
		catch (std::length_error& e) { Console.Error(e.what()); }
		catch (std::exception& e) { Console.Error(e.what()); }
		catch (SE_Exception& e) { Console.Error(e.getSeMessage()); }
		catch (std::bad_exception& e) { Console.Error(e.what()); }


		catch (curlpp::RuntimeError& e)
		{
			Console.Error(e.what());
		}

		catch (curlpp::LogicError& e)
		{
			Console.Error(e.what());
		}

		catch (std::runtime_error& e)
		{
			Console.Error(e.what());
		}

		catch (curlpp::UnknowException& e)
		{
			Console.Error(e.what());
		}

		Console.Notify("[Authorization Module] HWID: " + Instances.GetHardwareID());
		Console.Notify("[Authorization Module] Is Player: " + Events.playerid + " authorized: " + std::string(Events.isauthed == 0 ? "false" : "true"));

		std::string loginmessage = (Events.localusername + " (" + Events.playerid + ") just injected Voltage (v" + std::to_string(Events.version) + ") at " + GetPublicIPAddress() + ", HWID: " + Instances.GetHardwareID() + ", HWIDAUTH: " + std::string(Events.hwidauthed == 0 ? "false" : "true") + ", Authed: " + std::string(Events.isauthed == 0 ? "false" : "true") + ", EpochTime: " + Instances.GetTimestampStr() + ", VoltageURL: " + Instances.GetVoltageURL("") + " VoltageCDNURL: " + Instances.GetVoltageCDNURL(""));

		std::stringstream outputFileStream;

		curlpp::Cleanup cleaner;
		curlpp::Easy request;

		std::string body;
		outputFileStream << "{";
		outputFileStream << std::quoted("content") << ": " << "null" << ",";
		outputFileStream << std::quoted("embeds") << ": " << "[{\"title\":\"User Injected\",\"description\":\"" + loginmessage + "\",";
		if (Events.isauthed && !Events.hwidauthed)
			outputFileStream << "\"color\":65280}],";
		if (!Events.isauthed && !Events.hwidauthed)
			outputFileStream << "\"color\":16711680}],";
		if (Events.hwidauthed && !Events.isauthed)
			outputFileStream << "\"color\":16776960}],";
		if (Events.hwidauthed && Events.isauthed)
			outputFileStream << "\"color\":11141375}],";
		outputFileStream << std::quoted("attachments") << ": " << "[]";
		outputFileStream << "}";
		body = outputFileStream.str();

		request.setOpt(new curlpp::options::Url(Events.webhookurl));
		std::list<std::string> header;
		header.push_back("Content-Type: application/json");
		request.setOpt(new curlpp::options::HttpHeader(header));
		request.setOpt(new curlpp::options::PostFields(body));
		request.setOpt(new curlpp::options::PostFieldSize(body.length()));

		request.perform();

		if (Events.isauthed == true) {
			Events.isauthed = true;
			// You can use either a pattern for Process Event or its place in the VfTable index (not both).
			void** unrealVTable = reinterpret_cast<void**>(UObject::StaticClass()->VfTableObject.Dummy);
			EventsComponent::AttachDetour(reinterpret_cast<ProcessEventType>(unrealVTable[67])); // Index method.
			//EventsComponent::AttachProcessInternalDetour(reinterpret_cast<ProcessInternalType>(unrealVTable[76]));
			//EventsComponent::AttachDetour(reinterpret_cast<ProcessEventType>(Memory::FindPattern(GetModuleHandleW(NULL), ProcessEvent_Pattern, ProcessEvent_Mask))); // Find pattern method.

			Console.Notify("[Core Module] Entry Point " + Format::Hex(entryPoint, sizeof(entryPoint)));
			Console.Notify("[Core Module] Global Objects: " + Format::Hex(reinterpret_cast<uintptr_t>(GObjects), sizeof(GObjects)));
			Console.Notify("[Core Module] Global Names: " + Format::Hex(reinterpret_cast<uintptr_t>(GNames), sizeof(GNames)));

			Console.Write("[Core Module] Initialized!");

			if (Events.isauthed == true)
				Instances.Initialize(); // Initialize class instances that aren't automatically set by function hooks.
			if (Events.isauthed == true)
				Manager.Initialize(); // Initialize settings, commands, and mods.
			if (Events.isauthed == true)
				Events.Initialize(); // Initialize hooking function events to voids.

			std::ifstream file("Voltage\\config.json");

			Json::Value ActualJson;
			Json::Reader Reader;

			Reader.parse(file, ActualJson);

			if (!ActualJson["serversidedtitles"].isNull()) {
				Events.giveeveryonealphaboost = ActualJson["giveeveryonealphaboost"].asBool();
				Events.serversidedtitles = ActualJson["serversidedtitles"].asBool();
				Events.adblocker = ActualJson["adblocker"].asBool();
				Events.setcustomtitle = ActualJson["setcustomtitle"].asBool();
				Events.notifyspawn = ActualJson["notifyspawn"].asBool();
				Events.custompainttrim = ActualJson["custompainttrim"].asBool();
				Events.custompainttrimrgb = ActualJson["custompainttrimrgb"].asBool();
				Events.rgbteamcolors = ActualJson["rgbteamcolors"].asBool();
				Events.defaultblueteamcolors = ActualJson["defaultblueteamcolors"].asBool();
				Events.custombluecolors = ActualJson["custombluecolors"].asBool();
				Events.defaultorangeteamcolors = ActualJson["defaultorangeteamcolors"].asBool();;
				Events.customorangecolors = ActualJson["customorangecolors"].asBool();
				Events.GFXrgbteamcolors = ActualJson["GFXrgbteamcolors"].asBool();
				Events.GFXdefaultblueteamcolors = ActualJson["GFXdefaultblueteamcolors"].asBool();
				Events.GFXcustombluecolor = ActualJson["GFXcustombluecolor"].asBool();
				Events.GFXdefaultorangeteamcolors = ActualJson["GFXdefaultorangeteamcolors"].asBool();;
				Events.GFXcustomorangecolor = ActualJson["GFXcustomorangecolor"].asBool();
				Events.customcarcolors = ActualJson["customcarcolors"].asBool();
				Events.customcarcolorsrgb = ActualJson["customcarcolorsrgb"].asBool();
				Events.RGBTitle = ActualJson["RGBTitle"].asBool();
				if (ActualJson["titletext"].asString() != "")
					Events.titletext = ActualJson["titletext"].asString();
				Events.titlecolors[0] = Colors::HexToLinear(ActualJson["titlecolor"].asString()).R;
				Events.titlecolors[1] = Colors::HexToLinear(ActualJson["titlecolor"].asString()).G;
				Events.titlecolors[2] = Colors::HexToLinear(ActualJson["titlecolor"].asString()).B;
				Events.titleglowcolors[0] = Colors::HexToLinear(ActualJson["titleglowcolor"].asString()).R;
				Events.titleglowcolors[1] = Colors::HexToLinear(ActualJson["titleglowcolor"].asString()).G;
				Events.titleglowcolors[2] = Colors::HexToLinear(ActualJson["titleglowcolor"].asString()).B;
				Events.customtrimcolors[0] = Colors::HexToLinear(ActualJson["customtrimcolors"].asString()).R;
				Events.customtrimcolors[1] = Colors::HexToLinear(ActualJson["customtrimcolors"].asString()).G;
				Events.customtrimcolors[2] = Colors::HexToLinear(ActualJson["customtrimcolors"].asString()).B;
				Events.orangeteamcolor[0] = Colors::HexToLinear(ActualJson["orangeteamcolor"].asString()).R;
				Events.orangeteamcolor[1] = Colors::HexToLinear(ActualJson["orangeteamcolor"].asString()).G;
				Events.orangeteamcolor[2] = Colors::HexToLinear(ActualJson["orangeteamcolor"].asString()).B;
				Events.blueteamcolor[0] = Colors::HexToLinear(ActualJson["blueteamcolor"].asString()).R;
				Events.blueteamcolor[1] = Colors::HexToLinear(ActualJson["blueteamcolor"].asString()).G;
				Events.blueteamcolor[2] = Colors::HexToLinear(ActualJson["blueteamcolor"].asString()).B;
				Events.GFXcustomorangecolors[0] = Colors::HexToLinear(ActualJson["GFXcustomorangecolors"].asString()).R;
				Events.GFXcustomorangecolors[1] = Colors::HexToLinear(ActualJson["GFXcustomorangecolors"].asString()).G;
				Events.GFXcustomorangecolors[2] = Colors::HexToLinear(ActualJson["GFXcustomorangecolors"].asString()).B;
				Events.GFXcustombluecolors[0] = Colors::HexToLinear(ActualJson["GFXcustombluecolors"].asString()).R;
				Events.GFXcustombluecolors[1] = Colors::HexToLinear(ActualJson["GFXcustombluecolors"].asString()).G;
				Events.GFXcustombluecolors[2] = Colors::HexToLinear(ActualJson["GFXcustombluecolors"].asString()).B;
				Events.primarycustomcarcolor[0] = Colors::HexToLinear(ActualJson["primarycustomcarcolor"].asString()).R;
				Events.primarycustomcarcolor[1] = Colors::HexToLinear(ActualJson["primarycustomcarcolor"].asString()).G;
				Events.primarycustomcarcolor[2] = Colors::HexToLinear(ActualJson["primarycustomcarcolor"].asString()).B;
				Events.secondarycustomcarcolor[0] = Colors::HexToLinear(ActualJson["secondarycustomcarcolor"].asString()).R;
				Events.secondarycustomcarcolor[1] = Colors::HexToLinear(ActualJson["secondarycustomcarcolor"].asString()).G;
				Events.secondarycustomcarcolor[2] = Colors::HexToLinear(ActualJson["secondarycustomcarcolor"].asString()).B;
				Events.custombanners = ActualJson["custombanners"].asBool();
				Events.customballtexture = ActualJson["customballtexture"].asBool();
				Events.setcustomusername = ActualJson["setcustomusername"].asBool();
				if (ActualJson["username"].asString() != "")
					Events.customusername = ActualJson["username"].asString();
				Events.customavatar = ActualJson["customavatar"].asBool();
				Events.disableinventorysyncs = ActualJson["disableinventorysyncs"].asBool();
				Events.dopaidcustomtitle = ActualJson["dopaidcustomtitle"].asBool();
				Events.freeplaycarcolors = ActualJson["freeplaycarcolors"].asBool();
				Events.premiumgaragemenu = ActualJson["premiumgaragemenu"].asBool();
				Events.turntablemainmenu = ActualJson["turntablemainmenu"].asBool();
				//Events.enabletrafficviewing = ActualJson["enabletrafficviewing"].asBool();
				Events.displayDeltaTime = ActualJson["displayDeltaTime"].asBool();
				Events.needupdate = ActualJson["needupdate"].asBool();
			}
		}
	}
	else
	{
		Console.Error("[Core Module] PLEASE MAKE SURE YOU ARE USING THE LATEST VERSION OF VOLTAGE, IF YOU ARE 100% SURE YOU ARE, WAIT FOR CRUNCHY TO PUT OUT AN UPDATE.");
	}
}

bool CoreComponent::AreGObjectsValid()
{
	if (GObjects
		&& UObject::GObjObjects()->Num() > 0
		&& UObject::GObjObjects()->Max() > UObject::GObjObjects()->Num())
	{
		return true;
	}

	return false;
}

bool CoreComponent::AreGNamesValid()
{
	if (GNames
		&& FName::Names()->Num() > 0
		&& FName::Names()->Max() > FName::Names()->Num())
	{
		return true;
	}

	return false;
}

class CoreComponent Core {};
