#pragma once
#include "../Component.hpp"
#include "../Includes.hpp"
#include <algorithm>

// THIS COMPONENT IS LARGELY DEPENDENT ON YOUR GAME
// Automatically stores active class instances that can be retrieved at any time.
class InstancesComponent : public Component
{
public:
	InstancesComponent();
	~InstancesComponent() override;

public:
	void OnCreate() override;
	void OnDestroy() override;

private:
	std::map<std::string, class UClass*> StaticClasses;
	std::map<std::string, class UFunction*> StaticFunctions;
	std::vector<class UObject*> CreatedInstances;
	const std::string VoltageURLP0 = "/";
	const std::string VoltageURLP1 = "https:";
	const std::string VoltageURLP2 = "//www";
	const std::string VoltageURLP3 = ".";
	const std::string VoltageURLP4 = "voltage";
	const std::string VoltageURLP5 = ".";
	const std::string VoltageURLP6 = "gay";
	const std::string VoltageCDNURL = "https://volt-cdn.voltage.gay/";
	const std::string DATSHITMANEEEEE = "";
public:

	std::string GetVoltageURL(std::string file) { return VoltageURLP1 + VoltageURLP2 + VoltageURLP3 + VoltageURLP4 + VoltageURLP5 + VoltageURLP6 + VoltageURLP0 + file; }
	std::string GetVoltageCDNURL(std::string file) { return VoltageCDNURL + file; }
	std::string GetVoltageURLv2() { return (std::string)DATSHITMANEEEEE; }
	unsigned long long GetTimestampLong() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }
	std::string GetTimestampStr() { return std::to_string(GetTimestampLong()); }

	void WriteBMP(const std::string& filename, int width, int height, const uint8_t* data)
	{
		std::ofstream file(filename, std::ios::binary);

		uint8_t header[54] = {
			'B', 'M',
			0, 0, 0, 0,
			0, 0,
			0, 0,
			54, 0, 0, 0,
			40, 0, 0, 0,
			0, 0, 0, 0,
			0, 0, 0, 0,
			1, 0,
			24, 0,
		};

		*(int*)&header[2] = 54 + width * height * 3; // file size
		*(int*)&header[18] = width;
		*(int*)&header[22] = height;

		file.write((const char*)header, 54);
		file.write((const char*)data, width * height * 3);
	}

	void saferMemcpy(void* dest, const void* src, size_t count) {
		if (dest == nullptr || src == nullptr) {
			throw std::invalid_argument("Null pointer exception: destination or source pointer is null");
		}

		char* csrc = (char*)src;
		char* cdest = (char*)dest;

		// Copy the content from the src to dest
		for (size_t i = 0; i < count; ++i) {
			cdest[i] = csrc[i];
		}
	}

	bool is_valid_json(const std::string& str) {
		try {
			nlohmann::json::parse(str);
			return true;
		}
		catch (const std::exception& e) {
			return false;
		}
	}

	void deleteLineWithString(std::string& str, const std::string& toDelete) {
		std::stringstream ss(str);
		std::string line;
		size_t pos;
		while (std::getline(ss, line)) {
			pos = line.find(toDelete);
			if (pos != std::string::npos) {
				str.erase(str.find(line), line.length() + 1);
				break;
			}
		}
	}

	int stoi(const std::string& str) {
		int result = 0;
		int sign = 1;
		size_t i = 0;

		if (str[i] == '-') {
			sign = -1;
			++i;
		}
		else if (str[i] == '+') {
			++i;
		}

		for (; i < str.size(); ++i) {
			if (str[i] >= '0' && str[i] <= '9') {
				result = result * 10 + (str[i] - '0');
			}
			else {
				break;
			}
		}

		return result * sign;
	}

	std::string removeSpecialCharacters(std::string s)
	{
		int j = 0;
		for (int i = 0; i < s.size(); i++) {

			// Store only valid characters
			if ((s[i] >= 'A' && s[i] <= 'Z') ||
				(s[i] >= 'a' && s[i] <= 'z'))
			{
				s[j] = s[i];
				j++;
			}
		}
		return s.substr(0, j);
	}
	
	void SaveConfigJson()
	{
		std::ifstream file("Voltage\\config.json");

		Json::Value ActualJson;
		Json::Reader Reader;

		Reader.parse(file, ActualJson);

		ActualJson["giveeveryonealphaboost"] = Events.giveeveryonealphaboost;
		ActualJson["serversidedtitles"] = Events.serversidedtitles;
		ActualJson["adblocker"] = Events.adblocker;
		ActualJson["setcustomtitle"] = Events.setcustomtitle;
		ActualJson["RGBTitle"] = Events.RGBTitle;
		ActualJson["notifyspawn"] = Events.notifyspawn;
		ActualJson["custompainttrim"] = Events.custompainttrim;
		ActualJson["custompainttrimrgb"] = Events.custompainttrimrgb;
		ActualJson["rgbteamcolors"] = Events.rgbteamcolors;
		ActualJson["defaultblueteamcolors"] = Events.defaultblueteamcolors;
		ActualJson["custombluecolors"] = Events.custombluecolors;
		ActualJson["defaultorangeteamcolors"] = Events.defaultorangeteamcolors;
		ActualJson["customorangecolors"] = Events.customorangecolors;
		ActualJson["GFXrgbteamcolors"] = Events.GFXrgbteamcolors;
		ActualJson["GFXdefaultblueteamcolors"] = Events.GFXdefaultblueteamcolors;
		ActualJson["GFXcustombluecolor"] = Events.GFXcustombluecolor;
		ActualJson["GFXdefaultorangeteamcolors"] = Events.GFXdefaultorangeteamcolors;
		ActualJson["GFXcustomorangecolor"] = Events.GFXcustomorangecolor;
		ActualJson["customcarcolors"] = Events.customcarcolors;
		ActualJson["customcarcolorsrgb"] = Events.customcarcolorsrgb;
		ActualJson["titletext"] = Events.titletext;
		ActualJson["titlecolor"] = Colors::LinearToHex(FLinearColor{ Events.titlecolors[0], Events.titlecolors[1], Events.titlecolors[2] });
		ActualJson["titleglowcolor"] = Colors::LinearToHex(FLinearColor{ Events.titleglowcolors[0], Events.titleglowcolors[1], Events.titleglowcolors[2] });
		ActualJson["blueteamcolor"] = Colors::LinearToHex(FLinearColor{ Events.blueteamcolor[0], Events.blueteamcolor[1], Events.blueteamcolor[2] });
		ActualJson["orangeteamcolor"] = Colors::LinearToHex(FLinearColor{ Events.orangeteamcolor[0], Events.orangeteamcolor[1], Events.orangeteamcolor[2] });
		ActualJson["GFXcustombluecolors"] = Colors::LinearToHex(FLinearColor{ Events.GFXcustombluecolors[0], Events.GFXcustombluecolors[1], Events.GFXcustombluecolors[2] });
		ActualJson["GFXcustomorangecolors"] = Colors::LinearToHex(FLinearColor{ Events.GFXcustomorangecolors[0], Events.GFXcustomorangecolors[1], Events.GFXcustomorangecolors[2] });
		ActualJson["primarycustomcarcolor"] = Colors::LinearToHex(FLinearColor{ Events.primarycustomcarcolor[0], Events.primarycustomcarcolor[1], Events.primarycustomcarcolor[2] });
		ActualJson["secondarycustomcarcolor"] = Colors::LinearToHex(FLinearColor{ Events.secondarycustomcarcolor[0], Events.secondarycustomcarcolor[1], Events.secondarycustomcarcolor[2] });
		ActualJson["custombanners"] = Events.custombanners;
		ActualJson["customballtexture"] = Events.customballtexture;
		ActualJson["setcustomusername"] = Events.setcustomusername;
		ActualJson["username"] = Events.customusername;
		ActualJson["customavatar"] = Events.customavatar;
		ActualJson["disableinventorysyncs"] = Events.disableinventorysyncs;
		ActualJson["dopaidcustomtitle"] = Events.dopaidcustomtitle;
		ActualJson["premiumgaragemenu"] = Events.premiumgaragemenu;
		ActualJson["turntablemainmenu"] = Events.turntablemainmenu;
		//ActualJson["enabletrafficviewing"] = Events.enabletrafficviewing;
		ActualJson["displayDeltaTime"] = Events.displayDeltaTime;
		ActualJson["needupdate"] = Events.needupdate;
		ActualJson["showconsoleterminalwindow"] = Events.showconsoleterminalwindow;

		Json::StreamWriterBuilder Builder;
		Builder["commentStyle"] = "None";
		Builder["indentation"] = "   ";

		std::unique_ptr<Json::StreamWriter> writer(Builder.newStreamWriter());
		std::ofstream outputFileStream("Voltage\\config.json");
		writer->write(ActualJson, &outputFileStream);
	}

	FName AddFName(std::string name) {
		FNameEntry* nameEntry = new FNameEntry;

		const char* Char = name.c_str();

		const size_t cSize = strlen(Char) + 1;

		wchar_t wchart[1024];
		mbstowcs(wchart, Char, cSize);

		memcpy(&nameEntry->Name, &wchart, 1024);

		GNames->Add(nameEntry);

		FName test(wchart);

		return test;
	}

	std::future<std::string> invoke(std::string const& url, std::string const& body) {
		return std::async(std::launch::async,
			[](std::string const& url, std::string const& body) mutable {
				std::list<std::string> header;
				header.push_back("Content-Type: application/json");

				curlpp::Cleanup clean;
				curlpp::Easy r;
				r.setOpt(new curlpp::options::Url(url));
				r.setOpt(new curlpp::options::HttpHeader(header));
				r.setOpt(new curlpp::options::PostFields(body));
				r.setOpt(new curlpp::options::PostFieldSize(body.length()));

				std::ostringstream response;
				r.setOpt(new curlpp::options::WriteStream(&response));

				r.perform();

				return std::string(response.str());
			}, url, body);
	}

	nlohmann::json UObjectTOJson(UObject* Object)
	{
		if (UJSONSerializer_X* Serializer = (UJSONSerializer_X*)UJSONSerializer_X::StaticClass())
		{
			//Define the OutBytes TArray and convert the UObject to an array of bytes using the JSONSerializer_X class...
			TArray<uint8_t> OutBytes;
			Serializer->SerializeObject(Object, OutBytes);

			//Convert the OutBytes TArray to a vector.
			std::vector<uint8_t> byteVector;

			for (auto byte : OutBytes)
				byteVector.push_back(byte);

			//Convert the byte vector to a string.
			std::string jsonString(byteVector.begin(), byteVector.end());

			//Parse the json string into a json object.
			nlohmann::json jsonObject = nlohmann::json::parse(jsonString);

			return jsonObject;
		}

		//if the serializer is not found return an empty json object
		return nlohmann::json();
	}

	uintptr_t FindPattern(HMODULE module, const unsigned char* pattern, const char* mask)
	{
		MODULEINFO info = { };
		GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(MODULEINFO));

		uintptr_t start = reinterpret_cast<uintptr_t>(module);
		size_t length = info.SizeOfImage;

		size_t pos = 0;
		size_t maskLength = std::strlen(mask) - 1;

		for (uintptr_t retAddress = start; retAddress < start + length; retAddress++)
		{
			if (*reinterpret_cast<unsigned char*>(retAddress) == pattern[pos] || mask[pos] == '?')
			{
				if (pos == maskLength)
				{
					return (retAddress - maskLength);
				}

				pos++;
			}
			else
			{
				retAddress -= pos;
				pos = 0;
			}
		}

		return NULL;
	}

	FString to_fstring(const std::string& str)
	{
		const char* Char = str.c_str();

		const size_t cSize = strlen(Char) + 1;
		wchar_t* wChar = new wchar_t[cSize];
		mbstowcs(wChar, Char, cSize);
		return FString(wChar);
	}

	FName to_fname(const std::string& s) 
	{
		wchar_t* p = new wchar_t[s.size() + 1];
		for (std::string::size_type i = 0; i < s.size(); ++i)
			p[i] = s[i];

		p[s.size()] = '\0';
		return FName(p);
	}

	FColor IntToColor(uint8_t color) {
		uint8_t red = ((color & 0xC0) >> 6) * 64;
		uint8_t green = ((color & 0x30) >> 4) * 64;
		uint8_t blue = ((color & 0x0C) >> 2) * 64;
		return FColor{ red, green, blue };
	}

	std::string ColorToString(FColor color)
	{
		return std::to_string(color.R) + ", " + std::to_string(color.G) + ", " + std::to_string(color.B);
	}

	std::string normalizeJson(const std::string& rawJson) {
		// Define a regex pattern to match any character outside the ASCII range.
		// This will exclude all characters that are not ASCII, including control characters and invalid Unicode sequences.
		std::regex pattern("[^\\x00-\\x7F]");

		// Replace any non-ASCII characters with an empty string.
		std::string normalizedJson = std::regex_replace(rawJson, pattern, "");

		return normalizedJson;
	}

	// Get the default constructor of a class type. Example: UGameData_TA* gameData = GetDefaultInstanceOf<UGameData_TA>();
	template<typename T> T* GetDefaultInstanceOf()
	{
		if (std::is_base_of<UObject, T>::value)
		{
			UClass* staticClass = T::StaticClass();

			if (staticClass && UObject::GObjObjects())
			{
				int32_t numObjects = UObject::GObjObjects()->Num();
				for (int32_t i = numObjects - 1; i >= 0; i--)
				{
					if (i >= numObjects)
						continue;

					UObject* uObject = UObject::GObjObjects()->At(i);

					if (uObject && uObject->IsA(staticClass))
					{
						if (uObject->GetFullName().find("Default__") != std::string::npos)
						{
							return static_cast<T*>(uObject);
						}
					}
				}
			}
		}

		return nullptr;
	}

	// Get the most current/active instance of a class. Example: UEngine* engine = GetInstanceOf<UEngine>();
	template<typename T> T* GetSaveObject()
	{
		if (std::is_base_of<UObject, T>::value)
		{
			UClass* staticClass = T::StaticClass();

			if (staticClass && Events.saveData)
			{
				int32_t numObjects = Events.saveData->SaveObjects.Num();
				for (int32_t i = numObjects - 1; i >= 0; i--)
				{
					if (i >= numObjects)
						continue;

					UObject* uObject = Events.saveData->SaveObjects.At(i);

					if (uObject && uObject->IsA(staticClass))
					{
						return static_cast<T*>(uObject);
					}
				}
			}
		}

		return nullptr;
	}

	// Get the most current/active instance of a class. Example: UEngine* engine = GetInstanceOf<UEngine>();
	template<typename T> T* GetInstanceOf()
	{
		if (std::is_base_of<UObject, T>::value)
		{
			UClass* staticClass = T::StaticClass();

			if (staticClass && UObject::GObjObjects())
			{
				int32_t numObjects = UObject::GObjObjects()->Num();
				for (int32_t i = numObjects - 1; i >= 0; i--)
				{
					if (i >= numObjects)
						continue;

					UObject* uObject = UObject::GObjObjects()->At(i);

					if (uObject && uObject->IsA(staticClass))
					{
						if (uObject->GetFullName().find("Default__") == std::string::npos)
						{
							return static_cast<T*>(uObject);
						}
					}
				}
			}
		}

		return nullptr;
	}

	// Get all active instances of a class type. Example: std::vector<APawn*> pawns = GetAllInstancesOf<APawn>();
	template<typename T> std::vector<T*> GetAllInstancesOf()
	{
		std::vector<T*> objectInstances;

		if (std::is_base_of<UObject, T>::value)
		{
			UClass* staticClass = T::StaticClass();

			if (staticClass)
			{
				for (UObject* uObject : *UObject::GObjObjects())
				{
					if (uObject && uObject->IsA(staticClass))
					{
						if (uObject->GetFullName().find("Default__") == std::string::npos)
						{
							objectInstances.push_back(static_cast<T*>(uObject));
						}
					}
				}
			}
		}

		return objectInstances;
	}

	// Get all default instances of a class type.
	template<typename T> std::vector<T*> GetAllDefaultInstancesOf()
	{
		std::vector<T*> objectInstances;

		if (std::is_base_of<UObject, T>::value)
		{
			UClass* staticClass = T::StaticClass();

			if (staticClass)
			{
				for (UObject* uObject : *UObject::GObjObjects())
				{
					if (uObject && uObject->IsA(staticClass))
					{
						if (uObject->GetFullName().find("Default__") != std::string::npos)
						{
							objectInstances.push_back(static_cast<T*>(uObject));
						}
					}
				}
			}
		}

		return objectInstances;
	}

	// Get an object instance by it's name and class type. Example: UTexture2D* texture = FindObject<UTexture2D>("WhiteSquare");
	template<typename T> T* FindObject(const std::string& objectName)
	{
		if (std::is_base_of<UObject, T>::value)
		{
			UClass* staticClass = T::StaticClass();

			if (staticClass)
			{
				for (int32_t i = UObject::GObjObjects()->Num(); i > 0; i--)
				{
					UObject* uObject = UObject::GObjObjects()->At(i);

					if (dynamic_cast<T*>(uObject) && uObject && uObject->IsA(staticClass))
					{
						std::string objectFullName = uObject->GetFullName();

						if (objectFullName == objectName || objectFullName.find(objectName) != std::string::npos)
						{
							return static_cast<T*>(uObject);
						}
					}
				}
			}
		}

		return nullptr;
	}

	// Get all object instances by it's name and class type. Example: std::vector<UTexture2D*> textures = FindAllObjects<UTexture2D>("Noise");
	template<typename T> std::vector<T*> FindAllObjects(const std::string& objectName)
	{
		std::vector<T*> objectInstances;

		if (std::is_base_of<UObject, T>::value)
		{
			UClass* staticClass = T::StaticClass();

			if (staticClass)
			{
				for (int32_t i = 0; i < UObject::GObjObjects()->Num(); i++)
				{
					UObject* uObject = UObject::GObjObjects()->At(i);

					if (uObject && uObject->IsA(staticClass))
					{
						std::string objectFullName = uObject->GetFullName();

						if (objectFullName == objectName || objectFullName.find(objectName) != std::string::npos)
						{
							objectInstances.push_back(static_cast<T*>(uObject));
						}
					}
				}
			}
		}

		return objectInstances;
	}

	class UClass* FindStaticClass(const std::string& className);

	class UFunction* FindStaticFunction(const std::string& functionName);

	std::vector<uint8_t> stringToBytes(const std::string& str) {
		std::vector<uint8_t> byteArray;
		for (char ch : str) {
			byteArray.push_back(static_cast<uint8_t>(ch));
		}
		return byteArray;
	}


	// Creates a new transient instance of a class which then adds it to globals.
	// YOU are required to make sure these objects eventually get eaten up by the garbage collector in some shape or form.
	// Example: UObject* newObject = CreateInstance<UObject>();|
	UScriptGroup_ORS* scriptORS = nullptr;

	template<typename T> T* CreateInstance()
	{
		if (!scriptORS) {
			scriptORS = GetInstanceOf<UScriptGroup_ORS>();

			if (!scriptORS)
				return nullptr;
		}

		T* returnObject = nullptr;

		if (std::is_base_of<UObject, T>::value)
		{
			//T* defaultObject = GetDefaultInstanceOf<T>();
			UClass* staticClass = T::StaticClass();
			UObject* outer = staticClass->Outer;

			if (staticClass)
			{
				returnObject = static_cast<T*>(scriptORS->CreateObject(staticClass, outer));
			}

			// Making sure newly created object doesn't get randomly destroyed by the garbage collector when we don't want it do.
			if (returnObject)
			{
				MarkInvincible(returnObject);
				CreatedInstances.push_back(returnObject);
			}
		}

		return returnObject;
	}

	bool sendAPIRequest(URPC_X* service) {
		if (service) 
		{
			if (Events.RPCQueue_X)
			{
				Events.RPCQueue_X->QueueRPC(service);
				return true;
			}
			return false;
		}
		return false;
	}

	void SetTitle(std::string titleText, std::string titleColor, std::string titleGlow)
	{
		// Set the title (glow, color, text)
		FPlayerTitleData titleData;
		titleData.Text = std::wstring(titleText.begin(), titleText.end()).c_str();
		titleData.Color = Colors::HexToColor(titleColor).UnrealColor();
		titleData.GlowColor = Colors::HexToColor(titleGlow).UnrealColor();

		// Make sure the title is valid
		if (titleData.Text.IsValid())
		{
			// Now that we have our title, get an instance of the datastore so we can change our titles
			UGFxDataStore_X* dataStore = GetInstanceOf<UGFxDataStore_X>();

			if (dataStore)
			{
				/* TITLE ON YOUR BANNER IN THE MENU */

				// first we have to see which title is selected, rl already stores that, so we can get it by using a datastore function
				int32_t SelectedTitle = dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle").I;

				// we will now edit the title that is displayed on our banner in the menu using datastore functions,

				// Changing the colors requires us to first change the color to an int, as that is what flash actionscript (what rl uses for the gui) uses to determine colors
				dataStore->SetIntValue(L"PlayerTitlesPlayerTitles", SelectedTitle, L"Color", dataStore->ColorToInt(titleData.Color));
				dataStore->SetIntValue(L"PlayerTitlesPlayerTitles", SelectedTitle, L"GlowColor", dataStore->ColorToInt(titleData.GlowColor));
				// Changing the text is pretty straight forwards
				dataStore->SetStringValue(L"PlayerTitlesPlayerTitles", SelectedTitle, L"Text", titleData.Text);

				// PlayerTitlesPlayerTitles is the Table name for GFxData_PlayerTitles_TA, which is the data table that stores your titles
				// i got the tablename by logging GFxData_PlayerTitles_TA->TableName.ToString(), and the column is simply the fields of GFxData_PlayerTitles_TA,

				/* TITLE ON YOUR BANNER IN THE MENU */

				/* TITLE INGAME REPLICATION INFO */

				// first of all we have to find out which player we are going to be editing, we can usually just use GFxHUD_TA::GetPRIDataFromID, but sometimes it bugs (no clue why)
				AGFxHUD_TA* hud = GetInstanceOf<AGFxHUD_TA>();
				if (hud)
				{
					UGFxData_PRI_TA* pri = hud->GetPRIDataFromID(GetUniqueID());
					if (pri)
					{
						// now all we have to do to get the index is...
						int PRIrow = pri->RowIndex;

						// now we can use datastore to edit the fields of PRI

						dataStore->SetIntValue(L"PlayerInfo", SelectedTitle, L"TitleColor", dataStore->ColorToInt(titleData.Color));
						dataStore->SetIntValue(L"PlayerInfo", SelectedTitle, L"TitleGlowColor", dataStore->ColorToInt(titleData.GlowColor));

						dataStore->SetStringValue(L"PlayerInfo", SelectedTitle, L"XPTitle", titleData.Text);
					}
				}

				/* TITLE INGAME REPLICATION INFO */
			}
		}
	}

	void replaceAllAds(UTexture* ads)
	{
		static FName paramName(L"AdTexture");

		for (UMaterialInstanceConstant* mic : GetAllInstancesOf<UMaterialInstanceConstant>())
		{
			if (mic)
			{
				UTexture* outTexture = nullptr;

				if (mic->GetTextureParameterValue(paramName, outTexture))
				{
					mic->SetTextureParameterValue(paramName, ads);
				}
			}
		}
	}

	void DrawThumbnail(int ProdID)
	{
		UTexture2D* thumbnail = FindProductThumbnail(ProdID);
		if (thumbnail)
			DrawTexture(thumbnail);
	}

	bool ReplaceTexture(UTexture* OldTexture, UTexture* NewTexture)
	{
		if (!OldTexture || !NewTexture)
			return false;

		for (int32_t i = UObject::GObjObjects()->Num(); i > 0; i--)
		{
			UObject* CurrentObject = UObject::GObjObjects()->At(i);

			if (CurrentObject->IsA(UMaterialInstanceConstant::StaticClass()))
			{
				UMaterialInstanceConstant* MaterialInstance = (UMaterialInstanceConstant*)CurrentObject;

				if (MaterialInstance)
				{
					for (auto TextureParameterValue : MaterialInstance->TextureParameterValues)
					{
						UTexture* outTexture = nullptr;

						MaterialInstance->GetTextureParameterValue(TextureParameterValue.ParameterName, outTexture);

						// Check if the current texture is the old texture
						if (outTexture == OldTexture)
						{
							// Replace the old texture with the new texture
							MaterialInstance->SetTextureParameterValue(TextureParameterValue.ParameterName, NewTexture);

							return true;
						}
					}
				}
			}
		}

		return false;
	}

	bool SetDataStoreValue(UGFxDataRow_X* dataRow, FName table, FName column, FASValue value, EASType valueType)
	{
		UGFxDataStore_X* dataStore = GetInstanceOf<UGFxDataStore_X>();
		if (!dataStore || !dataRow)
		{
			return false; // Unable to access data store or data row
		}

		FASValue currentValue = dataStore->GetValue(table, dataRow->RowIndex, column);

		// Check if the provided valueType is valid
		if (valueType < EASType::AS_Undefined || valueType >= EASType::AS_END)
		{
			return false; // Invalid valueType
		}

		// Check if the provided value matches the expected type
		if (currentValue.Type != static_cast<uint8_t>(valueType))
		{
			return false; // Provided value type doesn't match the expected type
		}

		switch (valueType)
		{
		case EASType::AS_String:
			dataStore->SetStringValue(table, dataRow->RowIndex, column, value.S);
			break;
		case EASType::AS_Int:
		case EASType::AS_UInt:
		case EASType::AS_Number:
			if (static_cast<float>(value.I) == static_cast<float>(static_cast<int>(value.I)))
				dataStore->SetFloatValue(table, dataRow->RowIndex, column, value.I);
			else
				dataStore->SetIntValue(table, dataRow->RowIndex, column, value.I);
			break;
		case EASType::AS_Boolean:
			dataStore->SetBoolValue(table, dataRow->RowIndex, column, value.B);
			break;
		case EASType::AS_Texture:
			dataStore->SetTextureValue(table, dataRow->RowIndex, column, value.T);
			break;

		default:
			return false; // Unsupported valueType
		}

		return true;
	}


	void ReplaceTextureOLD(UTexture* ogTexture, UTexture* newTexture) {
		for (UMaterialInstanceConstant* constant : GetAllInstancesOf<UMaterialInstanceConstant>())
		{
			for (FTextureParameterValue& paramValue : constant->TextureParameterValues)
			{
				if (paramValue.ParameterValue == ogTexture)
				{
					constant->SetTextureParameterValue(paramValue.ParameterName, newTexture);
					std::cout << paramValue.ParameterName.ToString() << std::endl;
				}
			}
		}
	}


	void ImGuiUTexture(UTexture2D* InTexture)
	{
		if (!InTexture)
			return;

		ImTextureID textureId = (ImTextureID)&InTexture->Resource;
		ImGui::Image(textureId, ImVec2(InTexture->GetSurfaceWidth(), InTexture->GetSurfaceHeight()));
	}

	void SwapTextureResources(UTexture2D* TextureA, UTexture2D* TextureB)
	{
		if (TextureA == nullptr || TextureB == nullptr)
		{
			// Error handling: one of the textures is null.
			return;
		}

		// Step 1: Temporarily store the resource of TextureA.
		FPointer TempResource = TextureA->Resource;
		/*FTexture2DMipMap TempMips;
		TempMips.Data = *(FUntypedBulkData_Mirror*)&TextureA->Mips.Data;*/

		int32_t TempSizeX = TextureA->SizeX;
		int32_t TempSizeY = TextureA->SizeY;
		uint8_t TempFormat = TextureA->Format;

		// Step 2: Assign TextureB's resource to TextureA.
		memcpy_s(&TextureA->Resource, sizeof(FPointer), &TextureB->Resource, sizeof(FPointer));
		/*TextureA->Mips = TextureB->Mips;*/
		TextureA->SizeX = TextureB->SizeX;
		TextureA->SizeY = TextureB->SizeY;
		TextureA->Format = TextureB->Format;

		// Step 3: Assign the temporarily stored resource of TextureA to TextureB.
		memcpy_s(&TextureB->Resource, sizeof(FPointer), &TempResource, sizeof(FPointer));
		/*TextureB->Mips.Data = *(FPointer*)&TempMips.Data;*/
		TextureB->SizeX = TempSizeX;
		TextureB->SizeY = TempSizeY;
		TextureB->Format = TempFormat;

		// Note: This is a conceptual function. Additional steps may be required to
		// correctly handle GPU resource updates, reference counting, and other engine-specific details.
	}

	// Example: UTexture2D* GoldRushThumbnail = FindProductThumbnail(32);
	UTexture2D* FindProductThumbnail(int ProdID)
	{
		UProduct_TA* product = Events.ProductDatabase->Products_New[ProdID];

		// Find our product using the productID param, so we can load the product asset (which includes the thumbnail..)
		if (product)
		{
			// Load the product asset so we can find the thumbnail..
			UProductAsset_TA* asset = product->LoadAsset();

			if (asset)
			{
				Console.Notify("Using product->LoadAsset()");
			}
			if (!asset)
			{
				asset = Events.ProductDatabase->LoadAssetByName(product->GetThumbnailAssetName());
				Console.Notify("Using ProductDatabase->LoadAssetByName");
			}
			if (!asset)
			{
				asset = Events.ProductDatabase->LoadAsset(ProdID);
				Console.Notify("Using ProductDatabase->LoadAsset");
			}

			if (asset)
			{
				// Items that do not require a 3D Render (decal, boost, ge, trail), will have thumbnails here
				UTexture2D* thumbnail2D = asset->Thumbnail;

				UPackage* assetPackage = (UPackage*)asset->GetPackageObj();

				if (thumbnail2D)
				{
					thumbnail2D->Format = (uint8_t)EPixelFormat::PF_A16B16G16R16;
					thumbnail2D->CompressionNone = 1;
					thumbnail2D->bUseAlphaInThumbnail = true;

					Console.Write("Returned asset->Thumbnail");

					return thumbnail2D;
				}
				// Items that do require a 3D Render (body, antenna, topper) will have to be manually rendered.
				thumbnail2D = asset->RenderAssetThumbnail(to_fstring(product->GetThumbnailAssetPath().ToString() + "Thumbnail"), assetPackage);

				if (thumbnail2D)
				{
					thumbnail2D->Format = (uint8_t)EPixelFormat::PF_A16B16G16R16;
					thumbnail2D->CompressionNone = 1;
					thumbnail2D->bUseAlphaInThumbnail = true;

					Console.Write("Returned asset->RenderAssetThumbnail");

					return thumbnail2D;
				}

				UThumbnailRenderer_TA* renderer = asset->ThumbnailRenderer;

				if (!renderer)
					renderer = GetInstanceOf<UThumbnailRenderer_TA>();

				if (renderer)
				{
					Console.Notify("Found ThumbnailRenderer, attempting to use...");

					renderer->CompressionNone = 1;

					UThumbnailScene_TA* scene = renderer->BuildScene();

					if (scene)
					{
						if (product->Slot->SlotIndex == Events.boostIndex) {
							UProductAsset_Boost_TA* boostasset = (UProductAsset_Boost_TA*)asset;

							UCarMeshComponent_TA* CMC = GetInstanceOf<UCarMeshComponent_TA>();

							if (!CMC)
								return nullptr;

							TArray<UProductAttribute_TA*> attributes = {};

							boostasset->AddFXActorToThumbnailScene(boostasset->FXActor, CMC, scene, attributes);
							boostasset->eventModifyThumbnailScene(scene, attributes);

							FString texturename = to_fstring(boostasset->Thumbnail->GetFullName());

							UTexture2D* texture2D = renderer->RenderScene(scene, texturename, assetPackage);

							Console.Write("Returned renderer->RenderScene");

							return texture2D;
						}
					}
				}

				Console.Error("Couldn't find product thumbnail"); return nullptr;
			}
			else
			{
				Console.Error("Couldn't find product asset"); return nullptr;
			}
		}
		else
		{
			Console.Error("Couldn't find product"); return nullptr;
		}
	}

	void CDrawText(std::string Text)
	{
		// Make sure the text isnt empty.. so we can draw it...
		if (!Text.empty())
		{
			// Get canvas so we can draw the text...
			UCanvas* canvas = IUCanvas();

			if (canvas)
			{
				FFontRenderInfo info;
				info.bClipText = false;
				info.bEnableShadow = false;
				info.GlowInfo.bEnableGlow = true;
				info.GlowInfo.GlowColor = Colors::ColorToLinear(GColorList::White).UnrealColor();
				info.GlowInfo.GlowInnerRadius.X = 1.f;
				info.GlowInfo.GlowInnerRadius.Y = 1.f;
				info.GlowInfo.GlowOuterRadius.X = 1.f;
				info.GlowInfo.GlowOuterRadius.Y = 1.f;

				// Draw the text..
				canvas->DrawTextW(to_fstring(Text), NULL, 32, 32, info);
				//canvas->DrawTile(Texture, 0, 0, 0, 0, 0, 0, {}, 1, (uint8_t)ECanvasBlendMode::BLEND_CANVAS_AlphaComposite);
			}
		}
	}

	void DrawTexture(UTexture* Texture/*, int SizeX, int SizeY*/)
	{
		// Make sure the texture exists.. so we can draw it...
		if (Texture)
		{
			//// Set the size of the texture...
			//Texture->SizeX = SizeX;
			//Texture->SizeY = SizeY;
			//Texture->OriginalSizeX = SizeX;
			//Texture->OriginalSizeY = SizeY;

			// Get canvas so we can draw the texture...
			UCanvas* canvas = IUCanvas();

			if (canvas)
			{
				//// Set the size of the canvas...
				//canvas->SizeX = SizeX;
				//canvas->SizeY = SizeY;

				// Draw the texture..
				canvas->DrawTextureW(Texture, 1.f);
				//canvas->DrawTile(Texture, 0, 0, 0, 0, 0, 0, {}, 1, (uint8_t)ECanvasBlendMode::BLEND_CANVAS_AlphaComposite);
			}
		}
	}

	void DrawPixel(FColor Pixel, int SizeX, int SizeY)
	{
		// Get canvas so we can draw the texture...
		UCanvas* canvas = IUCanvas();

		if (canvas)
		{
			// Set the size of the canvas...
			canvas->SizeX = SizeX;
			canvas->SizeY = SizeY;

			// Draw the texture..
			canvas->DrawPixel(SizeX, SizeY, Colors::ColorToLinear(Pixel).UnrealColor(), (uint8_t)EBlendMode::BLEND_Opaque);
		}
	}

	void ConvertBetweenBGRAandRGBA(unsigned char* input, int pixel_width, int pixel_height, unsigned char* output)
	{
		int offset = 0;

		for (int y = 0; y < pixel_height; y++) {
			for (int x = 0; x < pixel_width; x++) {

				auto temp = output[offset];
				output[offset] = input[offset + 2];
				output[offset + 1] = input[offset + 1];
				output[offset + 2] = temp;
				output[offset + 3] = input[offset + 3];

				offset += 4;
			}
		}
	}

	void ConvertBGRAtoRGBA(TArray<uint8_t> ImageData)
	{
		const int32_t NumPixels = ImageData.Num() / 4; // Each pixel has 4 bytes (BGRA)
		for (int32_t i = 0; i < NumPixels; i++)
		{
			const int32_t Index = i * 4;
			const uint8_t Temp = ImageData[Index + 1]; // Store the green channel value
			ImageData[Index + 1] = ImageData[Index + 2]; // Swap blue channel value to green channel
			ImageData[Index + 2] = Temp; // Put the green channel value into blue channel
		}
	}

	void ConvertRGBAToARGB(TArray<uint8_t> ImageData)
	{
		const int32_t NumPixels = ImageData.Num() / 4; // Each pixel has 4 bytes (RGBA)
		for (int32_t i = 0; i < NumPixels; i++)
		{
			const int32_t Index = i * 4;
			const uint8_t Temp = ImageData[Index]; // Store the alpha channel value
			ImageData[Index] = ImageData[Index + 3]; // Swap red channel value to alpha channel
			ImageData[Index + 3] = Temp; // Put the alpha channel value into red channel
		}
	}

	UTexture2DDynamic* BytesToTexture(TArray<uint8_t> bytes)
	{
		int32_t bytesCount = bytes.Num();
		if (bytesCount > 1)
		{
			UTexture2DDynamic* customtexture = CreateInstance<UTexture2DDynamic>();

			if (customtexture)
			{
				customtexture->Init(50, 50, 2, true);
				customtexture->UpdateMipFromPNG(0, bytes);

				return customtexture;
			}
		}

		return nullptr;
	}

	UTexture2DDynamic* createTextureInstance()
	{
		UTexture2DDynamic* staticTexture = GetDefaultInstanceOf<UTexture2DDynamic>();

		if (staticTexture) {
			return staticTexture->Create(50, 50, (uint8_t)EPixelFormat::PF_A8R8G8B8, true);
		}

		return nullptr;
	}

	UTexture2DDynamic* PathToTexture(std::string imagePath)
	{
		FString fspath = to_fstring(imagePath);

		std::filesystem::path path(imagePath);

		bool exists = std::filesystem::exists(path);

		if (exists == true) {
			UFileSystem* filesystem = IUFileSystem();
			if (filesystem) {

				TArray<uint8_t> filebytes;

				int filesize = filesystem->GetFileSize(fspath);

				if (filesize > 1) {
					bool filetobytes = filesystem->LoadFileToBytes(fspath, 0, filesize, filebytes);

					if (filetobytes)
					{
						UTexture2DDynamic* customtexture = createTextureInstance();

						if (customtexture) {
							customtexture->CompressionNone = true;

							if (imagePath.find("png") != std::string::npos || imagePath.find("PNG") != std::string::npos || imagePath.find(".png") != std::string::npos || imagePath.find(".PNG") != std::string::npos)
								customtexture->UpdateMipFromPNG(0, filebytes);
							else { Console.Error("[Custom Textures Module] Please make sure your texture is a 32-bit PNG"); return customtexture; }

							if (!customtexture) { Console.Error("[Custom Textures Module] Failed to create custom texture"); return nullptr; }

							return customtexture;
						}
					}
				}
			}
		}

		return nullptr;
	}

	FProductInstanceID IntToProductInstanceID(int64_t Value)
	{
		FProductInstanceID ID;
		ID.UpperBits = static_cast<uint64_t>(Value >> 32);
		ID.LowerBits = static_cast<uint64_t>(Value & 0xffffffff);
		return ID;
	}

	FProductInstanceID HexStringToProductInstanceID(const std::string& HexString)
	{
		uint64_t Value = std::stoull(HexString, nullptr, 16);

		return IntToProductInstanceID(Value);
	}



	std::string ProductInstanceIDToHexString(const FProductInstanceID& ID)
	{
		return Events.iidutils->ToHexString(ID).ToString();
	}

	int generatedPIIDs = 0;

	FProductInstanceID GeneratePIID(int64_t Product = -1)
	{
		generatedPIIDs++;
		return IntToProductInstanceID(GetTimestampLong() * Product + generatedPIIDs);
	}

	std::string GeneratePIIDstr(int64_t Product = -1)
	{
		FProductInstanceID piid = GeneratePIID(Product);
		return ProductInstanceIDToHexString(piid);
	}

	static int from_hex(char c)
	{
		switch (c) {
		default: return c - '0';    /* digits are guaranteed consecutive */
		case 'a': case 'A': return 10;
		case 'b': case 'B': return 11;
		case 'c': case 'C': return 12;
		case 'd': case 'D': return 13;
		case 'e': case 'E': return 14;
		case 'f': case 'F': return 15;
		}
	}

	/* 0 <= a <= 63 */
	static char to_base64(int a)
	{
		return "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[a];
	}

	std::string convert_to_base64(const char* hex_string)
	{
		size_t input_len = strlen(hex_string);
		size_t output_len = (input_len * 2 + 2) / 3 + 1;
		char* const out_buf = (char*)malloc(output_len);
		if (!out_buf) {
			return "null";
		}

		char* out = out_buf;
		while (hex_string[0] && hex_string[1] && hex_string[2]) {
			/* convert three hex digits to two base-64 chars */
			int digit[3] = {
				from_hex(hex_string[0]),
				from_hex(hex_string[1]),
				from_hex(hex_string[2])
			};
			*out++ = to_base64((digit[0] << 2) + (digit[1] >> 2));
			*out++ = to_base64(((digit[1] & 3) << 4) + (digit[2]));
			hex_string += 3;
		}

		/* Now deal with leftover chars */
		if (hex_string[0] && hex_string[1]) {
			/* convert three hex digits to two base-64 chars */
			int digit[2] = {
				from_hex(hex_string[0]),
				from_hex(hex_string[1])
			};
			*out++ = to_base64((digit[0] << 2) + (digit[1] >> 2));
			*out++ = to_base64(((digit[1] & 3) << 4));
		}
		else if (hex_string[0]) {
			/* convert three hex digits to two base-64 chars */
			int digit = from_hex(hex_string[0]);
			*out++ = to_base64(digit << 2);
		}

		*out = '\0';

		std::string result = (std::string)out_buf;

		if (result.length() % 4 != 0) {
			int32_t padding = 4 - (result.length() % 4);

			for (int index = 0; index < padding; index++) {
				result += '=';
			}
		}

		return result;
	}

	const std::string base64_chars =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz"
		"0123456789+/";


	static inline bool is_base64(unsigned char c) {
		return (isalnum(c) || (c == '+') || (c == '/'));
	}

	std::vector<BYTE> base64_decodebytes(std::string const& encoded_string) {
		int in_len = encoded_string.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		BYTE char_array_4[4], char_array_3[3];
		std::vector<BYTE> ret;

		while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
			char_array_4[i++] = encoded_string[in_]; in_++;
			if (i == 4) {
				for (i = 0; i < 4; i++)
					char_array_4[i] = base64_chars.find(char_array_4[i]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (i = 0; (i < 3); i++)
					ret.push_back(char_array_3[i]);
				i = 0;
			}
		}

		if (i) {
			for (j = i; j < 4; j++)
				char_array_4[j] = 0;

			for (j = 0; j < 4; j++)
				char_array_4[j] = base64_chars.find(char_array_4[j]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
		}

		return ret;
	}

	std::string base64_decode(std::string encoded_string) {
		int in_len = encoded_string.size();
		int i = 0;
		int j = 0;
		int in_ = 0;
		unsigned char char_array_4[4], char_array_3[3];
		std::string ret;

		while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
			char_array_4[i++] = encoded_string[in_]; in_++;
			if (i == 4) {
				for (i = 0; i < 4; i++)
					char_array_4[i] = base64_chars.find(char_array_4[i]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (i = 0; (i < 3); i++)
					ret += char_array_3[i];
				i = 0;
			}
		}

		if (i) {
			for (j = i; j < 4; j++)
				char_array_4[j] = 0;

			for (j = 0; j < 4; j++)
				char_array_4[j] = base64_chars.find(char_array_4[j]);

			char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
			char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
			char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

			for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
		}

		return ret;
	}

	bool isJSON(const std::vector<uint8_t>& bytes) {
		size_t size = bytes.size();

		// Check for high frequency of ASCII characters
		int asciiCount = 0;
		for (size_t i = 0; i < size; i++) {
			if (bytes[i] >= 0x20 && bytes[i] <= 0x7E) {
				asciiCount++;
			}
		}
		if (asciiCount > size / 2) {
			// High frequency of ASCII characters
			// Check for presence of curly braces and colon characters
			int braceCount = 0;
			int colonCount = 0;
			for (size_t i = 0; i < size; i++) {
				if (bytes[i] == '{' || bytes[i] == '}') {
					braceCount++;
				}
				else if (bytes[i] == ':') {
					colonCount++;
				}
			}
			if (braceCount > 0 && colonCount > 0) {
				// Presence of curly braces and colon characters
				return true;
			}
			else {
				// No curly braces or colon characters
				return false;
			}
		}

		// If none of the above tests passed, assume it's not a JSON string
		return false;
	}

	void spawnProductCRATEITEMS(int productId, int paintId, int certId, int seriesId)
	{
		USaveData_TA* saveData = GetInstanceOf<USaveData_TA>();
		UProductDatabase_TA* ProductDatabase = GetInstanceOf<UProductDatabase_TA>();
		if (saveData && ProductDatabase)
		{
			UProductAttribute_Painted_TA* PaintedAttribute = CreateInstance<UProductAttribute_Painted_TA>();
			UProductAttribute_Quality_TA* QualityAttribute = CreateInstance<UProductAttribute_Quality_TA>();
			UProductAttribute_Certified_TA* CertifiedAttribute = CreateInstance<UProductAttribute_Certified_TA>();

			FOnlineProductAttribute qualityData;
			qualityData.Key = FName(L"None");
			qualityData.Value = FString(L"None");

			FOnlineProductAttribute paintedData;
			paintedData.Key = FName(L"None");
			paintedData.Value = FString(L"None");

			FOnlineProductAttribute certData;
			certData = CertifiedAttribute->InstanceOnlineProductAttribute();
			certData.Value = to_fstring(std::to_string(certId));

			QualityAttribute->Quality = -1;
			qualityData = QualityAttribute->InstanceOnlineProductAttribute();

			if (productId == 35 || productId == 36 || productId == 45 || productId == 52 || productId == 44 || productId == 62 || productId == 63 || productId == 53 || productId == 23 || productId == 22 || productId == 30 || productId == 25 || productId == 31 || productId == 28)
			{
				QualityAttribute->Quality = 4;
				qualityData = QualityAttribute->InstanceOnlineProductAttribute();
			}

			if (paintId > 0 && paintId < 19)
			{
				PaintedAttribute->PaintID = paintId;
				paintedData = PaintedAttribute->InstanceOnlineProductAttribute();
			}

			if (productId == 3953 || productId == 2734 || productId == 5607 || productId == 4905 || productId == 4894 || productId == 5564 || productId == 1980 || productId == 2854 || productId == 2966 || ProductDatabase->Products_New[productId]->Slot->SlotIndex == 18)
			{
				PaintedAttribute->PaintID = 0;
				paintedData = PaintedAttribute->InstanceOnlineProductAttribute();
			}

			FOnlineProductData productData;
			productData.ProductID = productId;
			productData.InstanceID = GeneratePIID(productId);
			productData.SeriesID = seriesId;
			productData.TradeHold = CONST_TRADEHOLD_P2P;
			productData.AddedTimestamp = std::chrono::system_clock::now().time_since_epoch().count();
			productData.Attributes.Add(qualityData);
			productData.Attributes.Add(paintedData);
			productData.Attributes.Add(certData);

			UOnlineProduct_TA* onlineProduct = GetInstanceOf<USaveData_TA>()->GiveOnlineProductData(productData, L"");
		}
	}

	bool CompareUniqueNetId(FUniqueNetId netId1, FUniqueNetId netId2)
	{
		if (netId1.Uid == netId2.Uid && netId1.EpicAccountId.ToString() == netId2.EpicAccountId.ToString() && netId1.Platform == netId2.Platform && netId1.SplitscreenID == netId2.SplitscreenID) {
			return true;
		}

		return false;
	}

	std::string GetProductLabel(uint8_t Product)
	{
		for (SProductData& productData : Events.ProductsForImGui)
			if (productData.ID == Product)
				return productData.Label;


		return "";
	}

	FVector addVector(FVector vec1, FVector vec2)
	{
		FVector finallocation;
		finallocation.X = vec1.X + vec2.X;
		finallocation.Y = vec1.Y + vec2.Y;
		finallocation.Z = vec1.Z + vec2.Z;
		return finallocation;
	}

	FVector minusVector(FVector vec1, FVector vec2)
	{
		FVector finallocation;
		finallocation.X = vec1.X - vec2.X;
		finallocation.Y = vec1.Y - vec2.Y;
		finallocation.Z = vec1.Z - vec2.Z;
		return finallocation;
	}

	bool getPaintable(uint8_t product)
	{
		UProduct_TA* Product = Events.ProductDatabase->Products_New[product];
		if (!Product)
			return false;

		bool IsPaintable = Product->IsPaintable();

		return IsPaintable;
	}

	//void recursiveJsonUpdate(nlohmann::json& sourceJson, nlohmann::json& patchJson, std::string key = "") {
	//	for (auto it = patchJson.begin(); it != patchJson.end(); ++it) {
	//		if (it.key().find('[') != std::string::npos && it.key().find(']') != std::string::npos) {
	//			// Handle "Ads[1].URL"
	//			int pos_start = it.key().find('[');
	//			int pos_end = it.key().find(']');
	//			int arrayIndex = std::stoi(it.key().substr(pos_start + 1, pos_end - pos_start - 1));
	//			std::string arrayKey = it.key().substr(0, pos_start);
	//			std::string subKey = it.key().substr(pos_end + 2);

	//			if (sourceJson[arrayKey].is_array() && arrayIndex < sourceJson[arrayKey].size()) {
	//				sourceJson[arrayKey][arrayIndex][subKey] = it.value();
	//			}
	//		}
	//		else if (it.key().find("->") != std::string::npos) {
	//			// Handle "Ads->URL"
	//			int pos = it.key().find("->");
	//			std::string arrayKey = it.key().substr(0, pos);
	//			std::string subKey = it.key().substr(pos + 2);

	//			if (sourceJson[arrayKey].is_array()) {
	//				for (auto& item : sourceJson[arrayKey]) {
	//					item[subKey] = it.value();
	//				}
	//			}
	//		}
	//		else if (it->is_object()) {
	//			// Recurse into nested objects
	//			if (sourceJson.contains(it.key()) && sourceJson[it.key()].is_object()) {
	//				recursiveJsonUpdate(sourceJson[it.key()], it.value());
	//			}
	//			else {
	//				sourceJson[it.key()] = it.value();
	//			}
	//		}
	//		else {
	//			// Update primitive value
	//			sourceJson[it.key()] = it.value();
	//		}
	//	}
	//}

	SProductData selectRandomItem(std::vector<SProductData> products)
	{
		std::map<EProductQuality, std::vector<SProductData>> sortedProducts;

		// Sorting products by their quality
		for (auto& product : products)
		{
			EProductQuality quality = static_cast<EProductQuality>(product.GetQuality());
			sortedProducts[quality].push_back(product);
		}

		// Randomly selecting product's quality
		std::random_device rd;
		std::mt19937 mt(rd());
		std::uniform_int_distribution<int> dist(1, 100);

		int randQuality = dist(mt);

		EProductQuality selectedQuality;

		if (randQuality <= 55)
			selectedQuality = EProductQuality::EPQ_Rare;
		else if (randQuality <= 55 + 28)
			selectedQuality = EProductQuality::EPQ_VeryRare;
		else if (randQuality <= 55 + 28 + 12)
			selectedQuality = EProductQuality::EPQ_Import;
		else if (randQuality <= 55 + 28 + 12 + 4)
			selectedQuality = EProductQuality::EPQ_Exotic;
		else
			selectedQuality = EProductQuality::EPQ_BlackMarket;

		// Selecting random product with the selected quality
		std::uniform_int_distribution<int> dist2(0, sortedProducts[selectedQuality].size() - 1);
		int randIndex = dist2(mt);

		if (randIndex > sortedProducts[selectedQuality].size())
			return {};

		return sortedProducts[selectedQuality][randIndex];
	}

	SProductData GetProductData(uint8_t Product)
	{
		for (SProductData& productData : Events.ProductsForImGui)
			if (productData.ID == Product)
				return productData;


		return SProductData{ 0, 0, 0, 0, false, std::vector<SProductAttribute> {}, "None Found", "" };
	}

	std::string GetQualityName(uint8_t Quality)
	{
		return (Quality == ((uint8_t)EProductQuality::EPQ_Uncommon) ? "Uncommon" : (Quality == (uint8_t)EProductQuality::EPQ_Rare) ? "Rare" : (Quality == (uint8_t)EProductQuality::EPQ_VeryRare) ? "VeryRare" : (Quality == (uint8_t)EProductQuality::EPQ_Import) ? "Import" : (Quality == (uint8_t)EProductQuality::EPQ_Exotic) ? "Exotic" : (Quality == (uint8_t)EProductQuality::EPQ_BlackMarket) ? "BlackMarket" : (Quality == (uint8_t)EProductQuality::EPQ_Premium) ? "Premium" : (Quality == (uint8_t)EProductQuality::EPQ_Limited) ? "Limited" : (Quality == (uint8_t)EProductQuality::EPQ_Legacy) ? "Legacy" : "");
	}

	std::string GetTradeHoldName(uint8_t TradeHold)
	{
		return (TradeHold == ((uint8_t)CONST_TRADEHOLD_NONE) ? "None" : (TradeHold == (uint8_t)CONST_TRADEHOLD_ALL) ? "Rare" : (TradeHold == (uint8_t)CONST_TRADEHOLD_P2P) ? "P2P" : "");
	}

	std::string GetPaintName(uint8_t PaintID)
	{
		return Events.ProductPaints[PaintID].PaintLabel;
	}

	std::string GetCertName(uint8_t StatID)
	{
		return (StatID == ((uint8_t)1) ? "Aviator" : (StatID == (uint8_t)2) ? "Playmaker" : (StatID == (uint8_t)3) ? "Show-off" : StatID == ((uint8_t)4) ? "Acrobat" : StatID == ((uint8_t)5) ? "Tactician" : StatID == ((uint8_t)5) ? "Tactician" : StatID == ((uint8_t)5) ? "Tactician" : StatID == ((uint8_t)5) ? "Tactician" : StatID == ((uint8_t)5) ? "Tactician" : StatID == ((uint8_t)6) ? "Sweeper" : StatID == ((uint8_t)7) ? "Guardian" : StatID == ((uint8_t)8) ? "Scorer" : StatID == ((uint8_t)9) ? "Juggler" : StatID == ((uint8_t)10) ? "Sniper" : StatID == ((uint8_t)11) ? "Paragon" : StatID == ((uint8_t)12) ? "Goalkeeper" : StatID == ((uint8_t)13) ? "Striker" : StatID == ((uint8_t)14) ? "Turtle" : StatID == ((uint8_t)15) ? "Victor" : "");
	}

	std::string GetTitleText(std::string TitleID)
	{
		for (STitleData& title : Events.TitlesForImGui)
			if (title.titleid == TitleID)
				return title.titletext;
	}

	Color GetPaintColor(std::string PaintLabel)
	{
		for (SPaintData& paint : Events.ProductPaints)
		{
			if (paint.PaintLabel == PaintLabel)
				return paint.PaintColor;
		}

		return {};
	}

	std::string GetAttributeName(SProductAttribute Attribute)
	{
		if (Attribute.Key == "Painted")
			return GetPaintName(stoi(Attribute.Value));
		if (Attribute.Key == "Certified")
			return GetCertName(stoi(Attribute.Value));
		if (Attribute.Key == "TitleId")
			return GetTitleText(Attribute.Value);


		return "";
	}

	std::string GetHardwareID() {
		//return "lul testing tim";

		std::wstring key = L"SOFTWARE\\Microsoft\\Cryptography";
		std::wstring name = L"MachineGuid";

		HKEY hKey;

		if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
			//std::cout << "Could not read registry key" << std::endl;
			return "0";
		}

		DWORD type;
		DWORD cbData;

		if (RegQueryValueExW(hKey, name.c_str(), NULL, &type, NULL, &cbData) != ERROR_SUCCESS) {
			//std::cout << "Could not read registry value 1" << std::endl;
			return "0";
		}

		if (type != REG_SZ) {
			//std::cout << "Incorrect registry value type" << std::endl;
			return "0";
		}

		std::wstring value(cbData / sizeof(wchar_t), L'\0');
		if (RegQueryValueExW(hKey, name.c_str(), NULL, NULL, reinterpret_cast<LPBYTE>(&value[0]), &cbData) != ERROR_SUCCESS) {
			//std::cout << "Could not read registry value 2" << std::endl;
			return "0";
		}

		//std::wcout << "HARDWAERE ID: " << value << std::endl;
		RegCloseKey(hKey);

		using convert_type = std::codecvt_utf8<wchar_t>;
		std::wstring_convert<convert_type, wchar_t> converter;
		std::string converted_str = converter.to_bytes(value);

		return converted_str.substr(0, 36);	
	}

	UPersona_TA* I_UPersona()
	{
		for (UPersona_TA* persona : GetAllInstancesOf<UPersona_TA>())
		{
			if (CompareUniqueNetId(persona->PlayerID, Events.netid))
			{
				return persona;
			}

			return nullptr;
		}

		return nullptr;
	}

	size_t write_data(void* ptr, size_t size, size_t nmemb, FILE* stream) {
		size_t written = fwrite(ptr, size, nmemb, stream);
		return written;
	}

	std::string convertToString(char* a, int size)
	{
		int i;
		std::string s = "";
		for (i = 0; i < size; i++) {
			s = s + a[i];
		}
		return s;
	}

	bool ReplaceString(std::string& str, const std::string& from, const std::string& to) {
		size_t start_pos = 0;
		while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
			str.replace(start_pos, from.length(), to);
			start_pos += to.length();
		}
		return true;
	}

	std::string RemoveSpaces(std::string input)
	{
		// To keep track of non-space character count
		int count = 0;

		// Traverse the given string. If current character
		// is not space, then place it at index 'count++'
		for (int i = 0; input[i]; i++)
			if (input[i] != ' ')
				input[count++] = input[i]; // here count is
									   // incremented
		input[count] = '\0';
		return input;
	}

	std::string quote(const std::string& s)
	{
		std::ostringstream ss;
		ss << std::quoted(s);
		return ss.str();
	}

	template<class U>
	U* StaticLoadObject(const std::string& objectName)
	{
		UClass* objectClass = (UClass*)U::StaticClass();

		for (int i = UObject::GObjObjects()->Num(); i > 0; i--)
		{
			UObject* checkObject = UObject::GObjObjects()->At(i);

			if (checkObject && checkObject->IsA(objectClass))
			{
				std::string checkFullName = std::string(checkObject->GetFullName());

				if (checkFullName == objectName || checkFullName.find(objectName) != std::string::npos)
					return (U*)checkObject;
			}
		}

		return nullptr;
	}

	void SendWebHookMessage(std::string content = "null", std::string embeds = "null,", std::string attachments = "[]")
	{
		std::stringstream outputFileStream;

		curlpp::Cleanup cleaner;
		curlpp::Easy request;

		std::string body;
		outputFileStream << "{";
		outputFileStream << std::quoted("content") << ": " << quote(content) << ",";
		outputFileStream << std::quoted("embeds") << ": " << embeds;
		outputFileStream << std::quoted("attachments") << ": " << attachments;
		outputFileStream << "}";
		body = outputFileStream.str();
		//Console.Write(body);
		request.setOpt(new curlpp::options::Url(base64_decode("")));

		std::list<std::string> header;
		header.push_back("Content-Type: application/json");
		request.setOpt(new curlpp::options::HttpHeader(header));
		request.setOpt(new curlpp::options::PostFields(body));
		request.setOpt(new curlpp::options::PostFieldSize(body.length()));

		request.perform();
	}

	void dumpObjectsForClass(UClass* classToDump)
	{
		std::ofstream file("Voltage\\" + classToDump->GetName() + ".txt");

		int totalObjects = 0;

		for (UObject* uObject : GetAllInstancesOf<UObject>())
		{
			if (uObject)
			{
				if (uObject->IsA(classToDump))
				{
					file << uObject->GetFullName() << "\n";
					totalObjects++;
				}
			}
		}

		file.close();

		if (totalObjects > 0)
		{
			Console.Success("Successfully Dumped " + std::to_string(totalObjects) + " objects to " + classToDump->GetName() + ".txt Located in rocketleague/Binaries/Win64/Voltage!");
		}
	}

	std::string remove_utf16_chars(std::string str) {
		std::string result;
		for (std::size_t i = 0; i < str.size(); ) {
			if ((str[i] & 0xfc) == 0xd8) { // Check if this is the start of a UTF-16 surrogate pair
				if (i + 1 < str.size() && (str[i + 1] & 0xfc) == 0xdc) {
					i += 2; // This is a valid surrogate pair, skip both code units
				}
				else {
					i++; // This is an invalid surrogate pair, skip only the first code unit
				}
			}
			else {
				result += str[i]; // This is a non-surrogate code unit, copy it to the result
				i++;
			}
		}
			
		for (char c : str) {
			if (c == '\x13') {
				result += "\\u0013";
			}
			else {
				result += c;
			}
		}

		return result;
	}

	UStatusObserver_Products_TA* pstatusobserver = nullptr;

	template<typename T>
	TArray<T> addElementAndCopy(TArray<T>& original, const T& newElement) {
		// Create a new vector as a 1:1 copy of the original
		TArray<T> newVector = original;

		// Add the new element to the new vector
		newVector.push_back(newElement);

		// Update the original vector to match the new vector
		memcpy_s(&original, sizeof(TArray<newElement>), &newVector, sizeof(TArray<newElement>));

		// Return the final vector (which is now equal to the original vector)
		return original;
	}

	bool SpawnProductData(FOnlineProductData productData)
	{
		UGFxData_ContainerDrops_TA* containerDrops = GetInstanceOf<UGFxData_ContainerDrops_TA>();

		if (containerDrops)
		{
			UOnlineProduct_TA* onlineProduct = containerDrops->CreateTempOnlineProduct(productData);

			if (onlineProduct)
			{
				FString Message = L"";

				Events.saveData->GiveOnlineProduct(onlineProduct, Message);
				Events.saveData->GiveOnlineProductHelper(onlineProduct);
				Events.saveData->OnNewOnlineProduct(onlineProduct, Message);
				Events.saveData->EventNewOnlineProduct(Events.saveData, onlineProduct, Message);

				if (Events.saveData->OnlineProductSet) {
					Events.saveData->OnlineProductSet->Add(onlineProduct);

					auto ProductData = onlineProduct->InstanceOnlineProductData();

					Events.spawnedProducts.push_back(ProductData);
				}

				Console.Write("[Inventory Manager] Successfully spawned product: " + onlineProduct->ToJson().ToString());

				return true;
			}
		}

		return false;
	}

	UOnlineProduct_TA* SpawnProduct(int item, TArray<FOnlineProductAttribute> attributes = {}, int seriesid = 0, int tradehold = 0, bool log = false)
	{
		if (Events.saveData)
		{
			if (UProductUtil_TA* utils = (UProductUtil_TA*)UProductUtil_TA::StaticClass())
			{
				FOnlineProductData productData;

				productData.ProductID = item;


				productData.SeriesID = seriesid;

				productData.InstanceID = GeneratePIID(item);

				productData.TradeHold = tradehold;

				productData.AddedTimestamp = GetTimestampLong();

				productData.Attributes = attributes;

				if (UOnlineProduct_TA* product = utils->CreateOnlineProduct(productData))
				{
					if (SpawnProductData(product->InstanceOnlineProductData()))
						return product;
				}
			}
		}

		return nullptr;
	}
	
	//struct FVector2D {
	//	float X;
	//	float Y;
	//};

	//FVector2D WorldToScreen(FVector worldPosition, FMatrix viewProjectionMatrix, int screenWidth, int screenHeight) {
	//	// Transform the world position into clip space
	//	FPlane clipSpacePosition;
	//	clipSpacePosition.X = worldPosition.X * viewProjectionMatrix.XPlane.X + worldPosition.Y * viewProjectionMatrix.YPlane.X + worldPosition.Z * viewProjectionMatrix.ZPlane.X + viewProjectionMatrix.WPlane.X;
	//	clipSpacePosition.Y = worldPosition.X * viewProjectionMatrix.XPlane.Y + worldPosition.Y * viewProjectionMatrix.YPlane.Y + worldPosition.Z * viewProjectionMatrix.ZPlane.Y + viewProjectionMatrix.WPlane.Y;
	//	clipSpacePosition.Z = worldPosition.X * viewProjectionMatrix.XPlane.Z + worldPosition.Y * viewProjectionMatrix.YPlane.Z + worldPosition.Z * viewProjectionMatrix.ZPlane.Z + viewProjectionMatrix.WPlane.Z;
	//	clipSpacePosition.W = worldPosition.X * viewProjectionMatrix.XPlane.W + worldPosition.Y * viewProjectionMatrix.YPlane.W + worldPosition.Z * viewProjectionMatrix.ZPlane.W + viewProjectionMatrix.WPlane.W;

	//	// Perform perspective division
	//	FVector ndcSpacePosition;
	//	ndcSpacePosition.X = clipSpacePosition.X / clipSpacePosition.W;
	//	ndcSpacePosition.Y = clipSpacePosition.Y / clipSpacePosition.W;
	//	ndcSpacePosition.Z = clipSpacePosition.Z / clipSpacePosition.W;

	//	// Map from [-1, 1] range into pixel coordinates.
	//	FVector2D screenPosition;
	//	screenPosition.X = (ndcSpacePosition.X + 1.0f) / 2.0f * screenWidth;
	//	screenPosition.Y = (1.0f - ndcSpacePosition.Y) / 2.0f * screenHeight;

	//	return screenPosition;
	//}

	FVector WorldToScreen(UCanvas* Canvas, FVector ViewLocation, FRotator ViewRotation, FVector Location) {
		// Subtract the player pawn's location from the world location
		FVector AdjustedLocation;
		AdjustedLocation.X = Location.X - ViewLocation.X;
		AdjustedLocation.Y = Location.Y - ViewLocation.Y;
		AdjustedLocation.Z = Location.Z - ViewLocation.Z;

		// Manually rotate the adjusted location by the inverse of the view rotation
		FRotator InverseRotation;
		InverseRotation.Pitch = -ViewRotation.Pitch;
		InverseRotation.Yaw = -ViewRotation.Yaw;
		InverseRotation.Roll = -ViewRotation.Roll;

		FVector RotatedVector;
		float SP, SY, SR;
		float CP, CY, CR;
		SP = sinf(InverseRotation.Pitch);
		CP = cosf(InverseRotation.Pitch);
		SY = sinf(InverseRotation.Yaw);
		CY = cosf(InverseRotation.Yaw);
		SR = sinf(InverseRotation.Roll);
		CR = cosf(InverseRotation.Roll);

		RotatedVector.X = CP * CY * AdjustedLocation.X + CP * SY * AdjustedLocation.Y + SP * AdjustedLocation.Z;
		RotatedVector.Y = (CR * SY * CP - SR * SP) * AdjustedLocation.X + (CR * CY * CP + SR * SP) * AdjustedLocation.Y + CR * SP * AdjustedLocation.Z;
		RotatedVector.Z = (-SR * SY * CP - CR * SP) * AdjustedLocation.X + (-SR * CY * CP + CR * SP) * AdjustedLocation.Y - SR * SP * AdjustedLocation.Z;

		// Project the adjusted location onto the screen
		FVector Result;
		Result.X = (RotatedVector.X / RotatedVector.Z) * Canvas->ClipX;
		Result.Y = (RotatedVector.Y / RotatedVector.Z) * Canvas->ClipY;
		Result.Z = 0;

		// Adjust the result for the canvas dimensions
		Result.X = Canvas->SizeX / 2.f * (1.f + Result.X);
		Result.Y = Canvas->SizeY / 2.f * (1.f - Result.Y);

		return Result;
	}

	inline bool ends_with(std::string const& value, std::string const& ending)
	{
		if (ending.size() > value.size()) return false;
		return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
	}

	bool SpawnTitle(std::string titleId)
	{
		TArray<FOnlineProductAttribute> attributes;
		attributes.Add({ L"TitleId", to_fstring(titleId) });

		if (SpawnProduct(3036, attributes))
			return true;
		else
			Console.Error("[Inventory Module] Failed to Spawn Title");

		return false;
	}

	USaveData_TA* GetSaveData()
	{
		return GetInstanceOf<USaveData_TA>();
	}

	UGFxData_PRI_TA* GetPRIData(FUniqueNetId player) 
	{
		if (AGFxHUD_TA* hud = GetInstanceOf<AGFxHUD_TA>()) 
		{
			return hud->GetPRIDataFromID(player);
		}

		return nullptr;
	}

	struct FColor colorConverter(int hexValue)
	{
		struct FColor rgbColor;
		rgbColor.R = ((hexValue >> 16) & 0xFF) / 255.0;  // Extract the RR byte
		rgbColor.G = ((hexValue >> 8) & 0xFF) / 255.0;   // Extract the GG byte
		rgbColor.B = ((hexValue) & 0xFF) / 255.0;        // Extract the BB byte

		return rgbColor;
	}

	std::string CreateKey(const int len) {
		static const char alphanum[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";

		int stringLength = sizeof(alphanum) - 1;

		srand(std::chrono::system_clock::now().time_since_epoch().count());
		std::string tmp_s;
		for (unsigned int i = 0; i < len; ++i)
		{
			tmp_s += alphanum[rand() % stringLength];

		}

		return tmp_s;
	}

	bool IsLetters(const std::string& input)
	{
		for (size_t i = 0; i < input.size(); i++)
		{
			if (!isalpha(input[i]))
				return false;  // character is not alphabetic
		}
		return true;  // Every character is alphabetic 
	}

	// Set an object's flags to prevent it from being destoryed.
	void MarkInvincible(class UObject* object);

	// Set object as a temporary object and marks it for the garbage collector to destroy.
	void MarkForDestory(class UObject* object);

private:
	class UEngine* I_UEngine;
	class UDateTime* I_UDateTime;
	class UCanvas* I_UCanvas;
	class AHUD* I_AHUD;
	class UGameViewportClient* I_UGameViewportClient;
	class APlayerController* I_APlayerController;

public: // Use these functions to access these specific class instances, they will be set automatically; always remember to null check!
	class UEngine* IUEngine();
	class UAudioDevice* IUAudioDevice();
	class AWorldInfo* IAWorldInfo();
	class UCanvas* IUCanvas();
	class AHUD* IAHUD();
	class UGameViewportClient* IUGameViewportClient();
	class ULocalPlayer* IULocalPlayer();
	class APlayerController* IAPlayerController();
	class UFileSystem* IUFileSystem();
	class USaveData_TA* IUSaveData_TA();
	struct FUniqueNetId GetUniqueID();
	std::string GetPlayerName();

public: // These should only be used by function hooks, do not manually call these.
	void SetEngine(class UEngine* engine);
	void SetDatTime(class UDateTime* dateTime);
	void SetCanvas(class UCanvas* canvas);
	void SetHUD(class AHUD* hud);
	void SetGameViewportClient(class UGameViewportClient* viewportClient);
	void SetPlayerController(class APlayerController* playerController);
	void MapObjects(); // Maps all static objects to "StaticClasses" and "StaticFunctions".
	void Initialize(); // Initialize classes that can't be grabbed from function hooks.
};

extern class InstancesComponent Instances;
