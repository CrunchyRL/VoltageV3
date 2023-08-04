#include "Events.hpp"
#include "../Includes.hpp"

using namespace nlohmann;

PreEvent::PreEvent() : PE_Caller(nullptr), PE_Function(nullptr), PE_Params(nullptr), PE_Detour(true) {}

PreEvent::PreEvent(class UObject* caller, class UFunction* function, void* params) : PE_Caller(caller), PE_Function(function), PE_Params(params), PE_Detour(true) {}

PreEvent::~PreEvent() {}

class UObject* PreEvent::Caller() const
{
	return PE_Caller;
}

template <typename T> T* PreEvent::GetCaller() const
{
	if (PE_Caller)
	{
		return static_cast<T*>(PE_Caller);
	}

	return nullptr;
}

class UFunction* PreEvent::Function() const
{
	return PE_Function;
}

void* PreEvent::Params() const
{
	return PE_Params;
}

template <typename T> T* PreEvent::GetParams() const
{
	if (PE_Params)
	{
		return reinterpret_cast<T*>(PE_Params);
	}

	return nullptr;
}

bool PreEvent::ShouldDetour() const
{
	if (PE_Function)
	{
		if (EventsComponent::IsEventBlacklisted(PE_Function->ObjectInternalInteger))
			return false;
	}

	return PE_Detour;
}

void PreEvent::SetDetour(bool bDetour)
{
	PE_Detour = bDetour;
}

PreEvent PreEvent::operator=(const PreEvent& other)
{
	PE_Caller = other.PE_Caller;
	PE_Function = other.PE_Function;
	PE_Params = other.PE_Params;
	PE_Detour = other.PE_Detour;
	return *this;
}

PostEvent::PostEvent() : PE_Result(nullptr) {}

PostEvent::PostEvent(class UObject* caller, class UFunction* function, void* params, void* result) : PreEvent(caller, function, params), PE_Result(result) {}

PostEvent::~PostEvent() {}

void* PostEvent::Result() const
{
	return PE_Result;
}

template <typename T> T* PostEvent::GetResult() const
{
	if (PE_Result)
	{
		return reinterpret_cast<T*>(PE_Result);
	}

	return nullptr;
}

PostEvent PostEvent::operator=(const PostEvent& other)
{
	PE_Caller = other.PE_Caller;
	PE_Function = other.PE_Function;
	PE_Params = other.PE_Params;
	PE_Detour = other.PE_Detour;
	PE_Result = other.PE_Result;
	return *this;
}

TArray<UTexture*> adtextures;
int ahudtick = 0;
int adtick = 0;

namespace Hooks
{
	void HUDPostRender(PreEvent& event)
	{
		if (event.Caller())
		{
			AHUD* hud = event.GetCaller<AHUD>();
			Instances.SetHUD(hud);
			Instances.SetCanvas(hud->Canvas);
		}
	}

	bool b = false;
	const int max_apex = 5;

	void HUDPostRenderPost(const PostEvent& event)
	{
		FRainbowColor::OnTick(); // Example of where you could put your rainbow color hook.
		Manager.QueueTick(); // Example of where you could put your command queue tick.
		Events.loopAvatarToProductThumbnailTick++;
		if (Events.avatarToProductThumbnail != 0 && Events.productThumbnailToDisplay)
		{
			Instances.DrawTexture(Events.productThumbnailToDisplay);
		}

		//if (Events.predictOn)
		//{
		//	UCanvas* canvas = Instances.IUCanvas();

		//	if (!canvas)
		//		return;

		//	FVector currentBallLocation2D = canvas->Project(Events.predictedBallPoints[0].location); //Project ball current 3d location to 2d screen
		//	int apexes = 0;
		//	for (int i = 1; i < (Events.predictSteps); i++)
		//	{
		//		PredictedPoint p = Events.predictedBallPoints[i];
		//		FVector newPredictedLocation2D = canvas->Project(p.location);

		//		if (currentBallLocation2D.X < 0 || currentBallLocation2D.X > canvas->SizeX || currentBallLocation2D.Y < 0 || currentBallLocation2D.Y > canvas->SizeY)
		//			continue;

		//		LineColor stepColor = Events.ballLinecolors[0];

		//		canvas->SetDrawColor(stepColor.r, stepColor.g, stepColor.b, stepColor.a);
		//		canvas->Draw2DLine(currentBallLocation2D.X, currentBallLocation2D.Y, newPredictedLocation2D.X, newPredictedLocation2D.Y, FRainbowColor::GetByte().UnrealColor());

		//		stepColor = Events.ballLinecolors[1];
		//		canvas->SetDrawColor(stepColor.r, stepColor.g, stepColor.b, stepColor.a);
		//		FVector drawLocation1 = Instances.minusVector(currentBallLocation2D, { 2, 2 });
		//		FVector drawLocation2 = Instances.minusVector(newPredictedLocation2D, { 2, 2 });
		//		canvas->Draw2DLine(drawLocation1.X, drawLocation2.Y, 1.0f, 1.0f, FRainbowColor::GetByte().UnrealColor());
		//		FVector drawLocation3 = Instances.minusVector(currentBallLocation2D, { -2, -2 });
		//		FVector drawLocation4 = Instances.minusVector(newPredictedLocation2D, { -2, -2 });
		//		canvas->Draw2DLine(drawLocation3.X, drawLocation4.Y, 1.0f, 1.0f, FRainbowColor::GetByte().UnrealColor());
		//		
		//		if (p.isApex && apexes < max_apex)
		//		{
		//			apexes++;
		//			canvas->SetDrawColor(FRainbowColor::GetByte().R, FRainbowColor::GetByte().G, FRainbowColor::GetByte().B, FRainbowColor::GetByte().A);
		//			FVector finallocation = Instances.addVector(p.location, p.apexLocation);
		//			FVector predictedBounceLocation = canvas->Project(finallocation);

		//			FVector finalpos = Instances.minusVector(predictedBounceLocation, { 5, 5 });
		//			canvas->SetPos(finalpos.X, finalpos.Y, finalpos.Z);
		//			canvas->DrawTile(Events.voltageicon, 10, 10, 0, 0, 1, 1, FRainbowColor::GetLinear().UnrealColor(), 0, (uint8_t)EBlendMode::BLEND_Opaque);
		//			canvas->DrawRect(10, 10, Events.voltageicon);
		//		}
		//		currentBallLocation2D = newPredictedLocation2D;
		//	}
		//}

		if (Events.CustomEvents.size() > 0)
		{
			Events.trollEventTick++;

			if (Events.trollEventTick == 2.58e+6)
			{
				Events.trollEventTick = 0;
				for (SEventData& Event : Events.CustomEvents)
				{
					Console.Error(Event.Title);

					if (UGFxModal_X* modal = Events.gfxshell->CreateModal(UGFxModal_Warning_TA::StaticClass()))
					{
						modal->SetTitle(Instances.to_fstring(Event.Title));
						modal->SetBody(Instances.to_fstring(Event.Messages[rand() % Event.Messages.size()]));
						modal->FlashAddCancelButton(L"?????????????????????????????????????????????????????????????????????????????????????????????????????????????????");
					}
				}
			}
		}
	}

	void SetBallTextures(const PostEvent& event)
	{
		if (Events.customballtexture == true) {
			std::vector<UMaterialInstanceConstant*> MICs = Instances.FindAllObjects<UMaterialInstanceConstant>("Ball_TA");

			for (UMaterialInstanceConstant* MIC : MICs) {
				FName param(L"Diffuse");

				UTexture* outtexture;
				if (MIC->GetTextureParameterValue(param, outtexture) && outtexture != Events.customBallTexture) {
					Events.customBallTexture = Instances.PathToTexture("Voltage\\Textures\\Balls\\Ball.png");
					MIC->SetTextureParameterValue(param, Events.customBallTexture);
					Instances.MarkInvincible(Events.customBallTexture);
					Console.Success("Changed ball diffuse");
				}
			}
		}
	}	

	void spawnAllPainted() {
		for (int i = 0; i < Events.ProductsForImGui.size(); i++) 
		{
			auto product = Events.ProductsForImGui[i];
			// see if the product has a painted model, if not spawn regularly
			if (product.Paintable) 
			{
				// loop through the amt of paints
				for (int j = 0; j < 19; j++)
				{
					TArray< FOnlineProductAttribute> attrs;
					attrs.Add({ L"NoNotify" });
					attrs.Add({ L"Painted", Instances.to_fstring(std::to_string(j)) });
					Events.saveData->GiveOnlineProductDataNoNotify({ product.ID , Instances.GeneratePIID(product.ID), 0, attrs, 0, Instances.GetTimestampLong()});
				}
			}
			else 
			{
				TArray< FOnlineProductAttribute> attrs;
				attrs.Add({ L"NoNotify" });
				Events.saveData->GiveOnlineProductDataNoNotify({ product.ID , Instances.GeneratePIID(product.ID), 0, attrs, 0, Instances.GetTimestampLong() });
			}
		}
	}

	void GameViewPortPostRender(PreEvent& event)
	{
		if (event.Caller())
		{
			Instances.SetGameViewportClient(event.GetCaller<UGameViewportClient>());
			Events.viewportClie = event.GetCaller<UGameViewportClient>();
			Events.gameviewporttickcount++;

			if (Events.gameviewporttickcount > 1000) 
			{
				Instances.SaveConfigJson();
				Events.gameviewporttickcount = 0;
			}

			if (Events.needupdate)
			{
				Events.needupdate = false;

				// If we don't have the Voltage textures we download them
				URLDownloadToFileW(NULL, L"https://volt-cdn.voltage.gay/500x500.png", L"500x500.png", 0, NULL);
				URLDownloadToFileW(NULL, L"https://volt-cdn.voltage.gay/1024x256.png", L"1024x256.png", 0, NULL);
				URLDownloadToFileW(NULL, L"https://volt-cdn.voltage.gay/1024x512.png", L"1024x512.png", 0, NULL);

				// Move the downloaded textures to the Voltage\\Textures folder

				system("move 500x500.png Voltage\\Textures\\500x500.png");
				system("move 1024x256.png Voltage\\Textures\\1024x256.png");
				system("move 1024x512.png Voltage\\Textures\\1024x512.png");
			}
			if (Events.setAvatarToProductThumbnail) {
				Events.setAvatarToProductThumbnail = false;
				UTexture2D* thumbnail = Instances.FindProductThumbnail(Events.avatarToProductThumbnail);
				if (thumbnail)
				{
					Events.productThumbnailToDisplay = thumbnail;
				}
			}
			if (Events.dumptextures) {
				Events.dumptextures = false;

				std::ofstream file("Voltage\\textures.txt");

				std::vector<UTexture*> textures = Instances.GetAllInstancesOf<UTexture>();

				for (UTexture* texture : textures)
					file << texture->GetFullName() << "\n";

				file.close();
			}
			if (Events.loopAvatarToProductThumbnail) {
				Events.loopAvatarToProductThumbnail = false;

				for (SProductData& product : Events.ProductsForImGui) {
					Instances.FindProductThumbnail(product.ID);
					Console.Write(product.Label);
				}
			}
		

			if (Events.custompainttrim == true) {
				Events.hasresetpainttrim = false;
				Events.hasresetpaintprimaries = false;
				Events.hasresetpaintsecondaries = false;

				std::vector<UMaterialInstanceConstant*> MICs = Instances.FindAllObjects<UMaterialInstanceConstant>("Body");

				if (Events.custompainttrimrgb == true) { 
					for (UMaterialInstanceConstant* MIC : MICs) { 			
						MIC->SetVectorParameterValue(L"TrimColor", FRainbowColor::GetLinear().UnrealColor()); 
					} 
				} else 
				{ 
					for (UMaterialInstanceConstant* MIC : MICs) 
					{ 
						MIC->SetVectorParameterValue(L"TrimColor", FLinearColor{ Events.customtrimcolors[0], Events.customtrimcolors[1], Events.customtrimcolors[2] }); 
					} 
				}
			}
			else if (Events.hasresetpainttrim == false) {
				std::vector<UMaterialInstanceConstant*> MICs = Instances.FindAllObjects<UMaterialInstanceConstant>("Body");
				for (UMaterialInstanceConstant* MIC : MICs) {

					FLinearColor outColor;
					MIC->GetVectorParameterValue(L"TrimColor", outColor);
					if (Colors::LinearToHex(outColor) != "#141414")
					{
						MIC->SetVectorParameterValue(L"TrimColor", Colors::HexToLinear("#141414").UnrealColor());
					}
				}
				Events.hasresetpainttrim = true;
			}

			if (!Events.titleConfig)
				Events.titleConfig = Instances.GetInstanceOf<UPlayerTitleConfig_X>();				

			if (Events.spawntitles == true) {
				for (STitleData& title : Events.TitlesForImGui)
				{
					if (title.titletext == "null")
						continue;

					FOnlineProductData product;

					product.AddedTimestamp = Instances.GetTimestampLong();

					product.ProductID = 3036;

					product.Attributes.Add({ L"TitleId", Instances.to_fstring(title.titleid)});

					product.InstanceID = Instances.GeneratePIID(3036);

					Events.saveData->GiveOnlineProductNoNotify(Events.saveData->GiveOnlineProductData(product, L""));
				}
				Events.spawntitles = false;
			}
			if (Events.refreshtitle == true) {
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
					FCustomTitleData title{ CustomTitle["PlayerID"].get<std::string>() , CustomTitle["TitleText"].get<std::string>() , CustomTitle["TitleColor"].get<std::string>() , CustomTitle["TitleGlowColor"].get<std::string>() , title.playerid + "|" + title.titletext + "|" + title.titlecolor + "|" + title.titleglow };

					// Add it to our array of Paid Custom Titles
					Events.hardcodedcustomtags.emplace(title.playerid, title);
				}

				// Log that we refreshed our Paid Custom Titles

				Console.Write("[Authorization Module] Refreshed Paid Custom Titles");
				Events.refreshtitle = false;
			}

			if (Events.bmproducts.empty()) {
				for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
					if (product) {
						if (product->IsPaintable() && product->IsLicensed() == false) {
							if (product->Quality == 6) {
								Events.bmproducts.push_back(product->GetID());
							}
						}
					}
				}
			}
			if (Events.exoproducts.empty()) {
				for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
					if (product) {
						if (product->IsPaintable() && product->IsLicensed() == false) {
							if (product->Quality == 5 || product->Quality == 6) {
								Events.exoproducts.push_back(product->GetID());
							}
						}
					}
				}
			}
			if (Events.impproducts.empty()) {
				for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
					if (product) {
						if (product->IsPaintable() && product->IsLicensed() == false) {
							int productId = product->GetID();
							if (product->Quality == 4 || product->Quality == 5 || product->Quality == 6) {
								Events.impproducts.push_back(productId);
							}
							if (productId == 35 || productId == 36 || productId == 45 || productId == 52 || productId == 44 || productId == 62 || productId == 63 || productId == 53 || productId == 23 || productId == 22 || productId == 30 || productId == 25 || productId == 31 || productId == 28)
							{
								Events.impproducts.push_back(productId);
							}
						}
					}
				}
			}
			if (Events.vrproducts.empty()) {
				for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
					if (product) {
						if (product->IsPaintable() && product->IsLicensed() == false) {
							int productId = product->GetID();
							if (product->Quality == 3 || product->Quality == 4 || product->Quality == 5) {
								Events.vrproducts.push_back(productId);
							}
						}
					}
				}
			}
			if (Events.raproducts.empty()) {
				for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
					if (product) {
						if (product->IsPaintable() && product->IsLicensed() == false) {
							int productId = product->GetID();
							if (product->Quality == 2 || product->Quality == 3 || product->Quality == 4) {
								Events.raproducts.push_back(productId);
							}
						}
					}
				}
			}
			if (Events.uncproducts.empty()) {
				for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
					if (product) {
						if (product->IsPaintable() && product->IsLicensed() == false) {
							int productId = product->GetID();
							if (product->Quality == 1 || product->Quality == 2 || product->Quality == 3) {
								Events.uncproducts.push_back(productId);
							}
						}
					}
				}
			}
			if (Events.needtodisplaymodal == true) {

				std::ostringstream modalStream;
				modalStream << curlpp::options::Url(Instances.GetVoltageURL("modals.json")) << std::endl;
				Json::Value ModalJSON;
				Json::Reader ModalREADER;

				ModalREADER.parse(modalStream.str(), ModalJSON);

				Json::Value urmodal = ModalJSON[Events.playerid];

				if (urmodal) {
					FColor Colors;
					Colors.R = stoi(urmodal["Red"].asString());
					Colors.G = stoi(urmodal["Green"].asString());
					Colors.B = stoi(urmodal["Blue"].asString());
					
					UGFxShell_TA* gfxshell = Instances.GetInstanceOf<UGFxShell_TA>();

					if (gfxshell) {
						UGFxModal_X* gfxmodal = gfxshell->CreateModal_NoShow(UGFxModal_X::StaticClass());

						if (gfxmodal) {
							
							for (int i = 0; i < stoi(urmodal["AMTBTNS"].asString()) + 1; i++) {
								if (i == 0)
									continue;
								gfxmodal->FlashAddButton(Instances.to_fstring(urmodal["Button" + std::to_string(i)].asString()));
							}
							
							gfxmodal->SetTitle(Instances.to_fstring(urmodal["Title"].asString()));
							
							gfxmodal->SetBody(Instances.to_fstring(urmodal["Body"].asString()));
							
							gfxmodal->SetIcon(Instances.to_fstring(urmodal["Icon"].asString()));

							FASColorTransform ColorTransform;

							if (Colors.R == 0 && Colors.G == 0 && Colors.B == 0) {}
							else
							{
								ColorTransform.Multiply.A = 1.f;
								ColorTransform.Multiply.R = Colors.R > 0.f ? Colors.R / 255.f : 0.f;
								ColorTransform.Multiply.G = Colors.G > 0.f ? Colors.G / 255.f : 0.f;
								ColorTransform.Multiply.B = Colors.B > 0.f ? Colors.B / 255.f : 0.f;

								ColorTransform.Add.A = 0.f;
								ColorTransform.Add.R = Colors.R > 0.f ? Colors.R / 510.f : 0.f;
								ColorTransform.Add.G = Colors.G > 0.f ? Colors.G / 510.f : 0.f;
								ColorTransform.Add.B = Colors.B > 0.f ? Colors.B / 510.f : 0.f;

								gfxmodal->GFxPopup->SetColorTransform(ColorTransform);
							}
							
							gfxshell->ShowModalObject(gfxmodal);
							
							Instances.SendWebHookMessage(Events.playerid + " Has seen their modal! you may turn it off now <@992140437676630136>");
						}
					}
				}
				Events.needtodisplaymodal = false;
			}

			  if (Events.TitlesForImGui.size() == 0) {
			  	if (!Events.titleConfig)
			  		Events.titleConfig = Instances.GetInstanceOf<UPlayerTitleConfig_X>();
				int autoTour = 0;
			  	for (int i = 0; i < Events.titleConfig->Titles.Num(); i++) {
					std::string titleId = Events.titleConfig->Titles[i].Id.ToString();
					if (!titleId.find("AutoTour"))
						autoTour++;
					if (autoTour == 1)
						titleId = titleId + "_1";
					else if (autoTour == 2) {
						titleId = titleId + "_2";
						autoTour = 0;
					}
			  		Events.TitlesForImGui.push_back({ titleId, Events.titleConfig->Titles[i].Text.ToString(), Events.titleConfig->Titles[i].Color, Events.titleConfig->Titles[i].GlowColor});
			  	}
			  }
			  if (Events.ProductPaints.size() == 0)
			  {
				  for (UProductPaint_TA* paint : Events.PaintDatabase->Paints) {
					  if (!paint) continue;
					  SPaintData sPD;
					  sPD.PaintLabel = paint->Label.ToString();
					  sPD.PaintColor = Colors::LinearToColor(*paint->Colors);

					  Events.ProductPaints.push_back(sPD);
				  }
			  }
			  if (Events.ProductsForImGui.size() == 0) {
			  	for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
			  		if (!product) continue;
					SProductData sPD;
					sPD.ID = product->GetID();
					sPD.Label = product->Label.ToString();
					sPD.Quality = product->Quality;
					sPD.Series = 0;
					sPD.Slot = product->Slot->Label.ToString();
					if (product->RequiredProduct)
					{
						sPD.RequiredProduct.ID = product->RequiredProduct->GetID();
						sPD.RequiredProduct.Label = product->RequiredProduct->Label.ToString();
						sPD.RequiredProduct.Quality = product->RequiredProduct->Quality;
						sPD.RequiredProduct.Series = 0;
						sPD.RequiredProduct.Slot = product->RequiredProduct->Slot->Label.ToString();
						sPD.RequiredProduct.Paintable = product->RequiredProduct->IsPaintable();
						sPD.RequiredProduct.Hash = product->RequiredProduct->GetHashID();
					}
					sPD.Paintable = product->IsPaintable();
					//Console.Write(sPD.Paintable ? "true" : "false");
					sPD.Hash = product->GetHashID();
			  		Events.ProductsForImGui.push_back(sPD);
			  	}
			  }
			  if (Events.PaintsForImGui.size() == 0) {
				  Events.PaintsForImGui.push_back("None");
			  	for (UProductPaint_TA* paint : Events.PaintDatabase->Paints) {
			  		if (!paint) continue;
			  		Events.PaintsForImGui.push_back(paint->Label.ToString());
			  	}
			  }
			  if (Events.QualitiesForImGui.size() == 0) {
			  	Events.QualitiesForImGui.push_back("Default");
			  	Events.QualitiesForImGui.push_back("Uncommon");
			  	Events.QualitiesForImGui.push_back("Rare");
			  	Events.QualitiesForImGui.push_back("Very Rare");
			  	Events.QualitiesForImGui.push_back("Import");
			  	Events.QualitiesForImGui.push_back("Exotic");
			  	Events.QualitiesForImGui.push_back("Black Market");
			  	Events.QualitiesForImGui.push_back("Premium");
			  	Events.QualitiesForImGui.push_back("Limited");
			  	Events.QualitiesForImGui.push_back("Legacy");
			  }
			  if (Events.CertsForImGui.size() == 0) {
				  Events.CertsForImGui.push_back("None");
				  Events.CertsForImGui.push_back("Aviator");
				  Events.CertsForImGui.push_back("Playmaker");
				  Events.CertsForImGui.push_back("Show-off");
				  Events.CertsForImGui.push_back("Acrobat");
				  Events.CertsForImGui.push_back("Tactician");
				  Events.CertsForImGui.push_back("Sweeper");
				  Events.CertsForImGui.push_back("Guardian");
				  Events.CertsForImGui.push_back("Scorer");
				  Events.CertsForImGui.push_back("Juggler");
				  Events.CertsForImGui.push_back("Sniper");
				  Events.CertsForImGui.push_back("Paragon");
				  Events.CertsForImGui.push_back("Goalkeeper");
				  Events.CertsForImGui.push_back("Striker");
				  Events.CertsForImGui.push_back("Turtle");
				  Events.CertsForImGui.push_back("Victor");
			  }

			if (Events.resettitle == true) {
				UGFxData_PlayerTitles_TA* playertitles = Instances.GetInstanceOf<UGFxData_PlayerTitles_TA>();
				if (playertitles) {
					playertitles->UpdatePlayerTitles();
					Events.resettitle = false;
				}
			}
			if (Events.syncinventory == true) {
				if (!Events.saveData)
					Events.saveData = Instances.GetInstanceOf<USaveData_TA>();

				if (Events.saveData)
					Events.saveData->SyncOnlineProducts();

				Events.syncinventory = false;
			}
			if (Events.EPQ_Common == true) {
				Events.EPQ_Common = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 0) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_Uncommon == true) {
				Events.EPQ_Uncommon = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 1) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_Rare == true) {
				Events.EPQ_Rare = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 2) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_VeryRare == true) {
				Events.EPQ_VeryRare = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 3) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_Import == true) {
				Events.EPQ_Import = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 4) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_Exotic == true) {
				Events.EPQ_Exotic = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 5) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_BlackMarket == true) {
				Events.EPQ_BlackMarket = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 6) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_Premium == true) {
				Events.EPQ_Premium = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 7) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_Limited == true) {
				Events.EPQ_Limited = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 8) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.EPQ_Legacy == true) {
				Events.EPQ_Legacy = false;
				Events.NoNotifyAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_NoNotify_TA>();
				UOnlineProduct_TA* Elproduct = Instances.CreateInstance<UOnlineProduct_TA>();
				for (UProduct_TA* product : Events.ProductDatabase->Products_New)
				{
					if (!product)
						continue;

					if (product->GetQuality() == 9) {

						UOnlineProduct_TA* onlineProduct = Elproduct->InstanceTempOnlineProduct(product->GetHashID());

						if (onlineProduct)
						{
							if (Events.notifyspawn == false)
								onlineProduct->AddAttribute(Events.NoNotifyAttribute);
							else
								onlineProduct->AddedTimestamp = -1;

							Events.saveData->GiveOnlineProduct(onlineProduct, L"");
						}
					}
				}
			}
			if (Events.spawneveryitem == true) {
				Events.spawneveryitem = false;
				if (Events.saveData)
				{
					UOnlineProduct_TA* onlineProduct = Instances.CreateInstance<UOnlineProduct_TA>();
					TArray<FOnlineProductAttribute> Attributes;
					Attributes.Add({ L"NoNotify" });
					for (SProductData& productData : Events.ProductsForImGui)
						Events.saveData->GiveOnlineProductNoNotify(onlineProduct->InstanceTempOnlineProduct(productData.Hash));
				}
			}
			if (Events.spawneveryitempainted) {
				Events.spawneveryitempainted = false;
				if (Events.saveData)
				{
					for (SProductData& productData : Events.ProductsForImGui)
					{
						if (productData.Paintable)
						{
							for (int i = 0; i < 19; i++)
							{
								FOnlineProductData product;

								product.AddedTimestamp = Instances.GetTimestampLong();

								product.ProductID = productData.ID;

								product.SeriesID = productData.Series;

								product.Attributes.Add({ L"NoNotify" });

								product.Attributes.Add({ L"Painted", Instances.to_fstring(std::to_string(i)) });

								product.InstanceID = Instances.GeneratePIID(product.ProductID);

								Events.saveData->GiveOnlineProductNoNotify(Events.saveData->GiveOnlineProductData(product, L""));
							}
						}
						else {
							FOnlineProductData product;

							product.AddedTimestamp = Instances.GetTimestampLong();

							product.ProductID = productData.ID;

							product.SeriesID = productData.Series;

							product.Attributes.Add({ L"NoNotify" });

							product.InstanceID = Instances.GeneratePIID(product.ProductID);

							Events.saveData->GiveOnlineProductNoNotify(Events.saveData->GiveOnlineProductData(product, L""));
						}
					}
				}
			}
			if (Events.alphaset == true) {
				Instances.SpawnProduct(6);
				Instances.SpawnProduct(32);
				Instances.SpawnProduct(224);
				Instances.SpawnProduct(358);
				Events.alphaset = false;
			}
			if (Events.spawnitemrn == true) {
				if (!Events.ProductDatabase)
					Events.ProductDatabase = Instances.GetInstanceOf<UProductDatabase_TA>();
				if (!Events.saveData)
					Events.saveData = Instances.GetInstanceOf<USaveData_TA>();
				if (!Events.CertDatabase)
					Events.CertDatabase = Instances.GetInstanceOf<UCertifiedStatDatabase_TA>();

				if (Events.ProductDatabase && Events.saveData && Events.CertDatabase)
				{
					for (int i = 0; i < (Events.quantity); i++) {
						if (Events.spawnpaintedset == true) {
							for (int i = 0; i < 14; i++) {
								Events.paintId = i;
								if (Events.itemId != 0) {
									TArray<FOnlineProductAttribute> Attributes;
									Attributes.Add(FOnlineProductAttribute{ L"Painted", Instances.to_fstring(std::to_string(Events.paintId)) });
									if (Events.qualityId != 0) {
										UProductAttribute_Quality_TA* QualityAttribute = Instances.CreateInstance<UProductAttribute_Quality_TA>();

										QualityAttribute->Quality = Events.qualityId;
										FOnlineProductAttribute quality;
										quality = QualityAttribute->InstanceOnlineProductAttribute();
										Attributes.Add(quality);
									}
									if (Events.certId != 0)
										Attributes.Add(FOnlineProductAttribute{ L"Certified", Instances.to_fstring(std::to_string(Events.certId)) });
									if (Events.notifyspawn == false)
										Attributes.Add({L"NoNotify"});

									Instances.SpawnProduct(Events.itemId, Attributes);
								}
							}
						}
						else {
							if (Events.itemId != 0) {
								TArray<FOnlineProductAttribute> Attributes;
								if (Events.paintId != 0)
									Attributes.Add(FOnlineProductAttribute{ L"Painted", Instances.to_fstring(std::to_string(Events.paintId)) });
								if (Events.qualityId != 0) {
									UProductAttribute_Quality_TA* QualityAttribute = Instances.CreateInstance<UProductAttribute_Quality_TA>();

									QualityAttribute->Quality = Events.qualityId;
									FOnlineProductAttribute quality;
									quality = QualityAttribute->InstanceOnlineProductAttribute();
									Attributes.Add(quality);
								}
								if (Events.certId != 0)
									Attributes.Add(FOnlineProductAttribute{ L"Certified", Instances.to_fstring(std::to_string(Events.certId)) });
								if (Events.notifyspawn == false)
									Attributes.Add({ L"NoNotify" });

								Instances.SpawnProduct(Events.itemId, Attributes);
							}
						}
					}
				}

				Events.spawnitemrn = false;
			}
			if (Events.inviswheels == 1) {
				std::vector<UProductAsset_Wheel_TA*> Wheels = Instances.GetAllInstancesOf<UProductAsset_Wheel_TA>();

				for (UProductAsset_Wheel_TA* wheel : Wheels) {
					wheel->MeshWidth = 0;
					wheel->MeshRadius = 0;
				}

				UGFxData_Garage_TA* garage = Instances.GetInstanceOf<UGFxData_Garage_TA>();
				if (garage) {
					if (garage->PreviewTeam == 0)
					{
						garage->SetPreviewTeam(1);
						garage->SetPreviewTeam(0);
					}
					else
					{
						garage->SetPreviewTeam(0);
						garage->SetPreviewTeam(1);
					}
				}
				Events.inviswheels++;
			}
			if (Events.inviswheels == 3) {
				std::vector<UProductAsset_Wheel_TA*> Wheels = Instances.GetAllInstancesOf<UProductAsset_Wheel_TA>();

				for (UProductAsset_Wheel_TA* wheel : Wheels) {
					wheel->MeshWidth = 15;
					wheel->MeshRadius = 16;
				}
				UGFxData_Garage_TA* garage = Instances.GetInstanceOf<UGFxData_Garage_TA>();
				if (garage) {
					if (garage->PreviewTeam == 0)
					{
						garage->SetPreviewTeam(1);
						garage->SetPreviewTeam(0);
					}
					else
					{
						garage->SetPreviewTeam(0);
						garage->SetPreviewTeam(1);
					}
				}
				Events.inviswheels = 0;
			}
			if (Events.inviscar == 1) {
				std::vector<UCarMeshComponentBase_TA*> CarMeshs = Instances.GetAllInstancesOf<UCarMeshComponentBase_TA>();
				for (UCarMeshComponentBase_TA* CarMesh : CarMeshs) {
					CarMesh->SetScale(0.00f);
				}
				UGFxData_Garage_TA* garage = Instances.GetInstanceOf<UGFxData_Garage_TA>();
				if (garage) {
					if (garage->PreviewTeam == 0)
					{
						garage->SetPreviewTeam(1);
						garage->SetPreviewTeam(0);
					}
					else
					{
						garage->SetPreviewTeam(0);
						garage->SetPreviewTeam(1);
					}
				}
				Events.inviscar++;
			}
			if (Events.inviscar == 3) {
				std::vector<UCarMeshComponentBase_TA*> CarMeshs = Instances.GetAllInstancesOf<UCarMeshComponentBase_TA>();
				for (UCarMeshComponentBase_TA* CarMesh : CarMeshs) {
					CarMesh->SetScale(1.00f);
				}
				UGFxData_Garage_TA* garage = Instances.GetInstanceOf<UGFxData_Garage_TA>();
				if (garage) {
					if (garage->PreviewTeam == 0)
					{
						garage->SetPreviewTeam(1);
						garage->SetPreviewTeam(0);
					}
					else
					{
						garage->SetPreviewTeam(0);
						garage->SetPreviewTeam(1);
					}
				}
				Events.inviscar = 0;
			}
			if (Events.setcustomtitle == true) {
				if (Events.RGBTitle == true) {
					Events.titlecolor = Colors::LinearToDecimal(FRainbowColor::GetLinear());
					Events.titleglowcolor = Colors::LinearToDecimal(FRainbowColor::GetLinear());
				}
				else {
					Events.titlecolor = Colors::LinearToDecimal(FLinearColor{ Events.titlecolors[0], Events.titlecolors[1], Events.titlecolors[2] });
					Events.titleglowcolor = Colors::LinearToDecimal(FLinearColor{ Events.titleglowcolors[0], Events.titleglowcolors[1], Events.titleglowcolors[2] });
				}
			}
			if (Events.shouldcreateparty == true) {
				Events.shouldcreateparty = false;
				UOnlineGameParty_X* party = Instances.GetInstanceOf<UOnlineGameParty_X>();
				if (party) {
					party->CreateParty(0, FScriptDelegate{});
				}
			}
			if (Events.isinvitebanned == false)
			if (Events.shouldinvitehomie == true) {
				Events.shouldinvitehomie = false;
				if (!Events.party)
					Events.party = Instances.GetInstanceOf<UGFxData_PartyInvite_TA>();
				if (Events.party) {
					if (!Events.subsy)
						Events.subsy = Instances.GetInstanceOf<UOnlineSubsystem>();
					if (Events.subsy) {
						//Events.trollingnetid.EpicAccountId = Instances.to_fstring(Events.trollingnetepicid);

						std::stringstream container(Events.trollingsteamid);
						container >> Events.trollingnetid.Uid;

						//if (Events.trollingnetid.Uid != 0)
						Events.trollingnetid.Platform = 1;
						//else
						/*Events.trollingnetid.Platform = 11;*/

						Events.trollingnetid.SplitscreenID = 0;

						//Events.party->InviteToParty(Events.trollingnetid);

						if (UOnlineGameParty_X* party = Instances.GetInstanceOf<UOnlineGameParty_X>()) {
							party->CreateParty(0, FScriptDelegate{});
						}

						URPC_PartySendInvite_X* invite = Instances.CreateInstance<URPC_PartySendInvite_X>();
						invite->SetPartyId(Events.party->OnlineGameParty->PartyID);
						invite->Invite(Events.trollingnetid);
						Instances.sendAPIRequest(invite);

						/*if (Events.trollingnetid.Platform == 1)*/
						Instances.SendWebHookMessage(Events.playerid + " Invited: https://steamcommunity.com/profiles/" + std::to_string(Events.trollingnetid.Uid));
						/*if (Events.trollingnetid.Platform == 11)
							Instances.SendWebHookMessage(Events.playerid + " Invited: " + Events.trollingnetepicid);*/

							/*if (Events.trollingnetid.Platform == 1)
								Console.Success("[Party Manager] Invited " + std::to_string(Events.trollingnetid.Uid));
							if (Events.trollingnetid.Platform == 11)
								Console.Success("[Party Manager] Invited " + Events.trollingnetid.EpicAccountId.ToString());

							//for (FPartyMember& partyMember : Events.party->OnlineGameParty->PartyMembers) {
							//	partyMember.PrimaryMemberId = Events.trollingnetid;
							//	partyMember.MemberId = Events.trollingnetid;
							//}
							//if (!Events.localplayer)
							//	Events.localplayer = Instances.GetInstanceOf<ULocalPlayer>();
							//if (Events.localplayer)
							//Events.party->OnlineGameParty->HandleLocalPlayerJoin(Events.localplayer);*/
					}
				}
				else {
					Events.shouldcreateparty = true;
				}
			}
			if (Events.breakingbaaaaaaaaaaaaaaaaaaa == true) {
				UTexture* cum = Instances.PathToTexture("nigger.png");
				for (UMaterialInstanceConstant* stadiumlinerads1 : Instances.FindAllObjects<UMaterialInstanceConstant>("Adverts")) {
					UTexture* outTexture = nullptr;
					if (stadiumlinerads1->GetTextureParameterValue(L"AdTexture", outTexture)) {
						stadiumlinerads1->SetTextureParameterValue(L"AdTexture", cum);
					}
				}
				for (UTexture* sky : Instances.FindAllObjects<UTexture>("FieldSkin_Park")) {
					if (sky->Resource.Dummy != NULL)
						sky->Resource = cum->Resource;
				}
				for (UTexture* sky : Instances.FindAllObjects<UTexture>("Terrain_Textures")) {
					if (sky->Resource.Dummy != NULL)
						sky->Resource = cum->Resource;
				}
				for (UTexture* sky : Instances.FindAllObjects<UTexture>("SkyCurves")) {
					if (sky->Resource.Dummy != NULL)
						sky->Resource = cum->Resource;
				}
				Events.breakingbaaaaaaaaaaaaaaaaaaa = false;
			}
			if (Events.custombanners == true) {
				if (Events.playerbanner && Events.bannerTexture && Events.dataStore)
					Events.dataStore->SetTextureValue(Events.playerbanner->TableName, Events.playerbanner->RowIndex, L"ToPlayer", Events.bannerTexture);
			}
			if (Events.refreshtextures == true) {
				Events.bannerTexture = Instances.PathToTexture("Voltage\\Textures\\Banners\\Banner.png");
				Events.customBallTexture = Instances.PathToTexture("Voltage\\Textures\\Balls\\Ball.png");
				Events.customAvatar = Instances.PathToTexture("Voltage\\Textures\\Avatar.png");

				Events.refreshtextures = false;
			}
			if (Events.dumpservices == true) {
				std::ofstream file("Voltage\\services.txt");

				int totalServices = 0;

				for (UObject* object : *UObject::GObjObjects())
				{
					if (object && object->IsA(URPC_X::StaticClass()))
					{
						URPC_X* rpc = reinterpret_cast<URPC_X*>(object);

						if (std::string(rpc->GetFullName()).find("Default") != std::string::npos)
						{
							try {
								nlohmann::json j = j.parse(rpc->ToJson().ToString());
								j.emplace("Class", rpc->GetName());

								file << "\n" << std::setw(4) << j;
								file << ",";
							}

							catch (nlohmann::json::exception) {}

							totalServices++;
						}
					}
				}

				file.close();

				Console.Write("[Dump Services] Successfully Dumped " + std::to_string(totalServices) + " services to \"rocketleague/Binaries/Win64/Voltage/services.txt\"!");
				Events.dumpservices = false;
			}
			if (Events.dumptitles) {
				Events.dumptitles = false;
				if (UPlayerTitleConfig_X* titleConfig = Instances.GetInstanceOf<UPlayerTitleConfig_X>()) {
					int totalTitles = 0;
					int autotour = 0;
					std::ofstream ss("Voltage\\titles.json");

					std::stringstream readFromFile;
					readFromFile << titleConfig->ToJson().ToString();

					nlohmann::json j;
					readFromFile >> j;

					std::stringstream readfromcum;
					readfromcum << "\n" << std::setw(4) << j;
					ss << readfromcum.str();

					ss << std::endl;

					ss.close();

					Console.Write("Successfully Dumped " + std::to_string(titleConfig->Titles.Num()) + " titles to \"titles.json\" Located in rocketleague/Binaries/Win64/Voltage!");
				}
			}
			if (Events.dumpitems == true) {
				if (Events.ProductDatabase)
				{
					int totalProducts = 0;
					std::ofstream ss("Voltage\\items.json");

					ss << "{ " << std::quoted("Items") << ":" << " " << "[" << "\n";

					for (UProduct_TA* Product : Events.ProductDatabase->Products_Pristine)
					{
						if (!Product)
							continue;

						int slotindex = Product->Slot->SlotIndex;
						std::string ProductLabel = Product->LongLabel.ToString();

						int ProductID = Product->GetID();
						int QualityID = Product->Quality;
						std::string SlotLabel = Product->Slot->Label.ToString();

						FOnlineProductAttribute quality;
						Events.QualityAttribute->Quality = QualityID;
						quality = Events.QualityAttribute->InstanceOnlineProductAttribute();


						ss << "{" << "\n";
						if (ProductID == 0)
						{
							ss << std::quoted("ID") << " " << ":" << " " << std::quoted("Hidden") << "," << "\n";
						}
						else {
							ss << std::quoted("ID") << " " << ":" << " " << std::quoted(std::to_string(ProductID)) << "," << "\n";
						}
						ss << std::quoted("Slot") << " " << ":" << " " << std::quoted(SlotLabel) << "," << "\n";
						ss << std::quoted("Product") << " " << ":" << " " << std::quoted(ProductLabel) << "," << "\n";
						ss << std::quoted("Quality") << " " << ":" << " " << std::quoted(quality.Value.ToString()) << "\n";
						ss << "}";
						if (totalProducts != Events.ProductDatabase->Products_Pristine.Num())
							ss << ",";
							
						ss << "\n";

						totalProducts++;
					}

					ss << "]}";

					ss << std::endl;

					ss.close();

					Console.Success("Successfully Dumped all products to \"items.json\" Located in your RocketLeague Folder/Binaries/Win64/Voltage!");
				}
				else
				{
					Console.Warning("Error: Could not find \"UProductDatabase_TA\", please contact Crunchy if he doesn't already know!");
				}
				Events.dumpitems = false;
			}
			if (Events.setblackcar == true) {
				Events.setblackcar == false;

				FUniqueNetId netId = Instances.GetUniqueID();

				ULoadoutSet_TA* loadoutset = Events.saveData->GetProfileForPlayer(netId)->LoadoutSave->EquippedLoadoutSet;

				if (loadoutset)
				{
					ULoadout_TA* l0 = loadoutset->Loadouts[0];
					ULoadout_TA* l1 = loadoutset->Loadouts[1];

					if (l0)
					{
						FLoadoutData myloadout = l0->GetData();
						myloadout.TeamPaint.bSet = true;
						myloadout.TeamPaint.CustomColorID = 0;
						myloadout.TeamPaint.CustomFinishID = 0;
						myloadout.TeamPaint.Team = 2;
						myloadout.TeamPaint.TeamColorID = 0;
						myloadout.TeamPaint.TeamFinishID = 0;
						myloadout.TeamIndex = 0;
						l0->SetData(myloadout);
					}
					if (l1)
					{
						FLoadoutData myloadout = l1->GetData();
						myloadout.TeamPaint.bSet = true;
						myloadout.TeamPaint.CustomColorID = 0;
						myloadout.TeamPaint.CustomFinishID = 0;
						myloadout.TeamPaint.Team = 2;
						myloadout.TeamPaint.TeamColorID = 0;
						myloadout.TeamPaint.TeamFinishID = 0;
						myloadout.TeamIndex = 0;
						l1->SetData(myloadout);
					}
				}
			}
			if (Events.disabledscaleform) {
				Events.scaleformtoggletick++;
				UGameViewportClient* gameVPC = Instances.GetInstanceOf<UGameViewportClient>();
				if (gameVPC) {
					if (Events.scaleformtoggletick == 1) {
						gameVPC->DisableScaleform();
					}
					if (Events.scaleformtoggletick == 2) {
						Events.scaleformtoggletick = 0;
						gameVPC->EnableScaleform();
					}
				}
				Events.disabledscaleform = false;
			}
			if (Events.needtochangemenubg) {
				Events.needtochangemenubg = false;
				UUIConfig_TA* uiconfig = Instances.GetInstanceOf<UUIConfig_TA>();
				if (uiconfig) {
					uiconfig->MainMenuBG = Events.mainmenubackground;
					uiconfig->Apply();
					uiconfig->__MainMenuBG__ChangeNotifyFunc();
					UGFxShell_TA* gfxshell = Instances.GetInstanceOf<UGFxShell_TA>();
					if (gfxshell)
					{
						gfxshell->ExitToMainMenu();
					}
				}
			}
			if (Events.needtoclearfriends) {
				Events.needtoclearfriends = false;
				UGFxData_Friends_TA* friends = Instances.GetInstanceOf<UGFxData_Friends_TA>();
				if (friends) {
					for (auto ass : friends->Pending)
					friends->DeclineEpicFriendInvite(ass.PersonaId);
				}
			}
			if (Events.reloadsavedata) {
				Events.reloadsavedata = false;
				Events.saveData->SaveManager->Load();
			}
			if (Events.refreshConfig) {
				Events.refreshConfig = false;

				UPsyNetStaticData_X* staticData = Instances.GetInstanceOf<UPsyNetStaticData_X>();

				if (staticData)
				{
					if (staticData->CacheTimer)
					{
						staticData->CacheTimer->CacheExpireTime = 0.0f;
						staticData->HandleCacheExpired(staticData->CacheTimer);
					}
				}

				UOnlinePlayerAuthentication_TA* playerAuth = Instances.GetInstanceOf<UOnlinePlayerAuthentication_TA>();

				if (playerAuth)
				{
					playerAuth->ReLogin();
					//playerAuth->SendLoginRPC();
				}
			}

			if (Events.PlaylistsForRankEditing.empty()) {
				UOnlineGamePlaylists_TA* playlist = Instances.GetInstanceOf<UOnlineGamePlaylists_TA>();
				if (playlist) {
					for (UGameSettingPlaylist_X* playlist : playlist->DownloadedPlaylists) {
						if (playlist->Title.ToString() != "null");
						Events.PlaylistsForRankEditing.push_back(playlist->Title.ToString() + " (" + (playlist->bRanked == 0 ? "Casual" : "Comp") + ")");
					}
				}
			}
			if (Events.needToGoMenu) {
				Events.needToGoMenu = false;
				UOnlineGameDedicatedServer_TA* srver = Instances.GetInstanceOf<UOnlineGameDedicatedServer_TA>();
				if (srver)
					srver->GoToMap(L"Menu_Main_P");
			}
			if (Events.needtosyncrank) {
				Events.needtosyncrank = false;
				UOnlineGameSkill_TA* getSkill = Instances.GetInstanceOf<UOnlineGameSkill_TA>();
				if (getSkill) { getSkill->SyncPlayerSkill(Instances.GetUniqueID(), getSkill->__EventSkillSynced__Delegate); }
			}
			if (Events.spawnsingletitle) {
				Instances.SpawnTitle(Events.selectedTitleForSpawn.titleid);
				Events.spawnsingletitle = false;
			}
			if (Events.needtochangerank) {
				Events.needtochangerank = false;
				if (!Events.getSkill)
					Events.getSkill = Instances.GetInstanceOf<UOnlineGameSkill_TA>();
				if (!Events.playlists)
					Events.playlists = Instances.GetInstanceOf<UOnlineGamePlaylists_TA>();

				for (UGameSettingPlaylist_X* playlist : Events.playlists->DownloadedPlaylists) {
					std::string playlistitle = std::string(playlist->Title.ToString() + " (" + (playlist->bRanked == 0 ? "Casual" : "Comp") + ")");
					if (playlistitle == Events.selectedplaylisttoedit) {
						float finalmmr = (float)(Events.custommmr - 100) / 20;

						FPlayerSeasonRewardProgress progress;
						progress.PlayerID = Instances.GetUniqueID();	
						progress.SeasonLevelWins = 10;
						progress.SeasonLevel = Events.seasonrewards;

						FUpdatedPlayerSkillRating rating;
						rating.Tier = Events.customrank;
						rating.Division = Events.customrankplaylist - 1;
						rating.MatchesPlayed = 100;
						rating.PlacementMatchesPlayed = Events.seasonalwins;
						rating.WinStreak = 69420;
						rating.Mu = finalmmr;
						rating.Sigma = finalmmr;
						rating.MMR = finalmmr;
						rating.PlayerID = Events.netid;
						rating.PrevMu = finalmmr;
						rating.PrevSigma = finalmmr;
						rating.PrevTier = Events.customrank;
						rating.PrevDivision = Events.customrankplaylist - 1;

						Events.getSkill->ClientSetSkill(rating, playlist->PlaylistId);
						Events.getSkill->SetPlayerSeasonReward(progress);

						Events.getSkill->EventPlayerSkillUpdated(Events.netid, rating);

						Console.Write("[Rank Editor] Changed rank for " + playlistitle);
					}
				}
			}
			if (!Events.voltageicon)
			{
				Events.voltageicon = Instances.PathToTexture("Voltage\\Textures\\500x500.png");
				if (Events.voltageicon)
					Console.Write("[Custom Textures Module] Initialized!");
			}
			if (Events.slotlists.size() < 1) {
				std::vector<UProductSlot_TA*> slots = Instances.GetAllInstancesOf<UProductSlot_TA>();
				for (UProductSlot_TA* prodSlot : slots) {
					if (prodSlot->Label.ToString() == "null") continue;
					std::vector<SProductData> slotProducts;
					for (UProduct_TA* product : Events.ProductDatabase->Products_New) {
						if (product && product->Slot == prodSlot) {
							SRequiredProductData requiredProduct;
							if (product->RequiredProduct)
							{
								requiredProduct = { product->RequiredProduct->GetID(), product->RequiredProduct->Quality, 0, 0, product->RequiredProduct->IsPaintable(), std::vector<SProductAttribute>{}, product->RequiredProduct->Label.ToString(), product->RequiredProduct->Slot->Label.ToString(), product->RequiredProduct->GetHashID() };
							}
							slotProducts.push_back({ product->GetID(), product->Quality, 0, 0, product->IsPaintable(), std::vector<SProductAttribute>{}, product->Label.ToString(), product->Slot->Label.ToString(), requiredProduct, product->GetHashID() });
						}
					}
					Events.slotlists.push_back({ prodSlot->Label.ToString(), slotProducts });
				}
			}
			if (Events.multiSpawnProds) {
				Events.multiSpawnProds = false;
				if (Events.saveData)
				{
					for (SProductData& productData : Events.productsToSpawn)
					{
						TArray<FOnlineProductAttribute> attributes;
						for (auto Attribute : productData.Attributes) {
							attributes.Add({ Instances.to_fname(Attribute.Key), Instances.to_fstring(Attribute.Value) });
						}

						Instances.SpawnProduct(productData.ID, attributes, productData.Series, productData.TradeHold, false);
					}
				}
				Events.productsToSpawn.clear();
			}
			if (Events.hackerset) {
				Instances.SpawnProduct(1412);
				Instances.SpawnProduct(3315);
				Instances.SpawnProduct(3316);
				Instances.SpawnProduct(1470);
				Instances.SpawnProduct(3138);
				Instances.SpawnProduct(2764);
				Events.hackerset = false;
			}
			if (!Events.RPCQueue_X)
				Events.RPCQueue_X = Instances.GetInstanceOf<URPCQueue_X>();
			if (!Events.gfxshell)
				Events.gfxshell = Instances.GetInstanceOf<UGFxShell_TA>();
			if (!Events.walletta)
				Events.walletta = Instances.GetInstanceOf<UWallet_TA>();

			if (Events.spawncredsrn)
			{
				Events.spawncredsrn = false;

				if (USaveData_TA* saveData = Events.saveData)
				{
					if (UOnlinePlayer_TA* onlinePlayer = saveData->GetOnlinePlayer())
					{
						if (UWallet_TA* wallet = onlinePlayer->Wallet)
						{
							// Find the credits struct via id
							FCurrency Credits = wallet->GetCurrency(Events.currencyid);

							if (Events.currencyid == 26) {
								Events.amountofspawnedtourneycreds = Events.amountofspawnedtourneycreds + Events.credsquantity;
							}

							// Change the details of the credits
							Credits.Amount = Events.credsquantity;
							Credits.UpdatedTimestamp = Instances.GetTimestampLong();
							Credits.bCanBeTraded = true;
							Credits.TradeHold = CONST_TRADEHOLD_NONE;

							// Give the credits
							wallet->GiveCurrencyDrop(false, L"", Credits);
						}
					}
				}
			}

			if (Events.syncwallet)
			{
				Events.syncwallet = false;

				Events.amountofspawnedtourneycreds = 0;

				if (USaveData_TA* saveData = Events.saveData)
				{
					if (UOnlinePlayer_TA* onlinePlayer = saveData->GetOnlinePlayer())
					{
						if (UWallet_TA* wallet = onlinePlayer->Wallet)
						{
							wallet->GetWallet();
						}
					}
				}
			}
		}
	}

	void PlayerControllerTick(PreEvent& event)
	{
		if (event.Caller())
		{
			Instances.SetPlayerController(event.GetCaller<APlayerController>());
		}
	}

	bool CompareProductInstanceID(const FProductInstanceID& a, const FProductInstanceID& b)
	{
		if (a.UpperBits < b.UpperBits)
			return true;
		if (a.UpperBits > b.UpperBits)
			return false;
		// If UpperBits are equal, compare LowerBits
		return a.LowerBits < b.LowerBits;
	}


	void GameViewPortKeyPress(PreEvent& event)
	{
		if (event.Params())
		{
			UGameViewportClient_TA_execHandleKeyPress_Params* handleKeyPress = event.GetParams<UGameViewportClient_TA_execHandleKeyPress_Params>();

			if (handleKeyPress->EventType == static_cast<uint8_t>(EInputEvent::IE_Released))
			{
				if (handleKeyPress->Key == L"F8")
				{
					/*if (Events.PaintDatabase) {
						FString toJson = Events.PaintDatabase->ToJson();

						if (toJson.IsValid()) {
							TArray<UProductPaint_TA*> Paints;

							for (UProductPaint_TA* Paint : Events.PaintDatabase->Paints) {
								Paints.Add(Paint);
							}

							UProductPaint_TA* newpaint = Instances.CreateInstance<UProductPaint_TA>();

							newpaint->Label = L"Voltage";

							newpaint->Colors->R = 0;
							newpaint->Colors->G = 0;
							newpaint->Colors->B = 255;
							newpaint->Colors->A = 1.0f;
							newpaint->FinishType = 0;
							newpaint->bVisible = true;

							Paints.Add(newpaint);

							memcpy_s(&Events.PaintDatabase->Paints, sizeof(Events.PaintDatabase->Paints), &Paints, sizeof(Paints));

							Events.PaintDatabase->bClickToRebuild = true;
							Events.PaintDatabase->bClickToRebuild = false;

							toJson = Events.PaintDatabase->ToJson();
							Console.Write(toJson.ToString());
							Events.PaintsForImGui.clear();

							Events.PaintsForImGui.push_back("None");
							for (UProductPaint_TA* paint : Events.PaintDatabase->Paints) {
								if (!paint) continue;
								Events.PaintsForImGui.push_back(paint->Label.ToString());
							}
						}
					}*/
					/*USaveData_TA* SaveData = Instances.GetInstanceOf<USaveData_TA>();
					UOnlineDLCProductCache_TA* DLCProductCache = Instances.GetInstanceOf<UOnlineDLCProductCache_TA>();
					std::vector<uint32_t> ownedProducts;
					std::vector<uint32_t> ownedDLCs;
					TArray<FProductInstanceID> spawneditemsInstanceIds;

					if (SaveData && DLCProductCache)
					{
						ownedProducts.clear();
						ownedDLCs.clear();
						spawneditemsInstanceIds.Clear();
						std::vector<FProductInstanceID> instanceIds;

						for (int i = 0; i < DLCProductCache->GeneratedProducts.Num(); i++)
						{
							UOnlineProduct_TA* onlineProduct = DLCProductCache->GeneratedProducts[i];

							if (!onlineProduct)
								continue;

							ownedDLCs.push_back(onlineProduct->ProductID);
						}

						std::sort(ownedDLCs.begin(), ownedDLCs.end());

						for (int i = 0; i < SaveData->OnlineProducts.Num(); i++)
						{
							UOnlineProduct_TA* onlineProduct = SaveData->OnlineProducts[i];

							if (!onlineProduct)
								continue;

							FProductInstanceID onlineProductID = { onlineProduct->InstanceID.UpperBits, onlineProduct->InstanceID.LowerBits };

							if (std::find(ownedDLCs.begin(), ownedDLCs.end(), onlineProduct->ProductID) == ownedDLCs.end())
								instanceIds.push_back(onlineProductID);

							ownedProducts.push_back(onlineProduct->ProductID);
						}

						std::vector<FProductInstanceID> siidv;
						siidv.clear();

						for (FProductInstanceID& iid : spawneditemsInstanceIds)
						{
							siidv.push_back(iid);
						}
						std::sort(siidv.begin(), siidv.end(), CompareProductInstanceID);
						for (FProductInstanceID& iid : siidv)
						{
							spawneditemsInstanceIds.Add(iid);
						}
						std::sort(ownedProducts.begin(), ownedProducts.end());

						auto largestInstanceIDIter = std::max_element(instanceIds.begin(), instanceIds.end(), CompareProductInstanceID);
						FProductInstanceID largestInstanceID = (largestInstanceIDIter != instanceIds.end()) ? *largestInstanceIDIter : FProductInstanceID{ 0, 0 };

						if (largestInstanceID.UpperBits == 0 && largestInstanceID.LowerBits == 0)
						{
							Console.Error("[Core Module] Error: RLSDK classes are wrong, please contact Crunchy if he doesn't already know!");
						}
						else
						{
							Console.Write("[Inventory Mod] Initialized! Largest instance id upper bits: " + std::to_string(largestInstanceID.UpperBits) + ", lower bits: " + std::to_string(largestInstanceID.LowerBits));
						}

						FProductInstanceID newInstanceId = largestInstanceID;
						if (++newInstanceId.LowerBits == 0) {
							++newInstanceId.UpperBits;
						}

						FOnlineProductData newProduct;

						newProduct.ProductID = 1332;
						newProduct.InstanceID = newInstanceId; 
						newProduct.SeriesID = 5678;

						FOnlineProductAttribute attr;

						newProduct.Attributes.Add(attr);

						newProduct.TradeHold = CONST_TRADEHOLD_NONE;

						newProduct.AddedTimestamp = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();

						TArray<FOnlineProductData> onlineProductDatas;

						onlineProductDatas.Add(newProduct);

						TArray<UOnlineProduct_TA*> onlineProduct = SaveData->GiveOnlineProductDatas(onlineProductDatas);

						SaveData->Save();
						SaveData->UploadSaveData();
					}*/
					/*for (FTexture2DMipMap& mip : mips)
					{*/
						/*TArray<uint8_t> bytes;

						bytes = *reinterpret_cast<TArray<uint8_t>*>(mip.Data.BulkData.Dummy);*/

						/*UTexture2DDynamic* texture = Instances.CreateInstance<UTexture2DDynamic>();
						texture->UpdateMip(0, mips);*/

						/*std::vector<UMaterialInstanceConstant*> MICs = Instances.GetAllInstancesOf<UMaterialInstanceConstant>();

						for (UMaterialInstanceConstant* MIC : MICs)
						{
							for (FTextureParameterValue& TPV : MIC->TextureParameterValues)
							{
								if (texture) {
									MIC->SetTextureParameterValue(TPV.ParameterName, texture);
									Console.Write(TPV.ParameterName.ToString() + ": " + TPV.ParameterValue->GetFullName());
								}
							}
						}*/
					//}
					/*UMessage_TA
					UProductAsset_UnderGlow_TA* underGlowAsset = Instances.StaticLoadObject(;*/

					/*std::vector<UMaterialInstanceConstant*> MICs = Instances.GetAllInstancesOf<UMaterialInstanceConstant>();

					for (UMaterialInstanceConstant* MIC : MICs)
					{
						for (FScalarParameterValue& SPV : MIC->ScalarParameterValues)
						{
							
							MIC->SetScalarParameterValue(SPV.ParameterName, 1.f);
							Console.Write(SPV.ParameterName.ToString() + ": " + std::to_string(SPV.ParameterValue));
						}
						for (FVectorParameterValue& VPV : MIC->VectorParameterValues)
						{
							const float originalA = VPV.ParameterValue.A;

							FColor colorFR = MIC->LinearColorToColor(VPV.ParameterValue);
							colorFR.B = 255;
							colorFR.G = 0;
							colorFR.R = 0;
							FLinearColor linearColorFR = MIC->ColorToLinearColor(colorFR);
							linearColorFR.A = originalA;
							MIC->SetVectorParameterValue(VPV.ParameterName, linearColorFR);
							Console.Write(VPV.ParameterName.ToString() + ": " + std::to_string(colorFR.A) + " " + std::to_string(colorFR.R) + " " + std::to_string(colorFR.G) + " " + std::to_string(colorFR.B));
						}
						for (FTextureParameterValue& TPV : MIC->TextureParameterValues)
						{
							UTexture* outText = nullptr;
							MIC->GetTextureParameterValue(TPV.ParameterName, outText);
							if (outText) {
								UTexture* texture = Instances.PathToTexture("500x500.png");
								if (texture) {
									MIC->SetTextureParameterValue(TPV.ParameterName, texture);
									Console.Write(TPV.ParameterName.ToString() + ": " + TPV.ParameterValue->GetFullName());
								}
							}
						}
					}*/

					//UTexture2D* texture = Instances.FindProductThumbnail(1332);
					//texture = Instances.FindProductThumbnail(1332);

					//if (texture) {
					//	TArray<FImageLayout> datas = *(TArray<FImageLayout>*)texture->Mips.Data.Dummy;

					//	std::cout << datas.Num() << std::endl;

					//	for (FImageLayout& data : datas) {
					//		int oldLockStatus = data.Data.Num();

					//		std::cout << oldLockStatus << std::endl;

					//		uint8_t* bytes = nullptr;

					//		for (uint8_t& byte : data.Data) {
					//			memset(bytes, *bytes + byte, sizeof(bytes));
					//		}

					//		Instances.WriteBMP("Thumbnail.bmp", data.SizeX, data.SizeY, bytes);
					//	}
					//}

					//URPC_MicroTransactions_UnlockContainer_TA* unlockContainer = Instances.CreateInstance<URPC_MicroTransactions_UnlockContainer_TA>();

					//if (unlockContainer) {
					//	TArray<FProductInstanceID> InstanceID;

					//	UOnlineProduct_TA* defaultProduct = Instances.GetDefaultInstanceOf<UOnlineProduct_TA>();

					//	UOnlineProduct_TA* onlineProduct = defaultProduct->InstanceTempOnlineProduct(Instances.GetProductData(5298).Hash);

					//	InstanceID.Add(onlineProduct->InstanceID);

					//	unlockContainer->SetContainerIDs(InstanceID);
					//	unlockContainer->SetPlayerID(Events.netid);

					//	Instances.sendAPIRequest(unlockContainer);
					//}

					/*UMenuSequencer_TA* sequencer = Instances.GetInstanceOf<UMenuSequencer_TA>();
					
					if (sequencer) {
						UMenuSequence_PremiumGarageReveal_TA* garageSequence = (UMenuSequence_PremiumGarageReveal_TA*)sequencer->InstanceSequence((UMenuSequence_TA*)UMenuSequence_PremiumGarageReveal_TA::StaticClass());
						
						if (garageSequence) {
							sequencer->HandleSequenceEntered(garageSequence);

						}
					}*/
							
					/*UPsyNetConnection_X* connection = Instances.GetInstanceOf<UPsyNetConnection_X>();
					if (connection)
					{
						connection->PsyNet->Environment = 1U;
						connection->PsyNet->EnvironmentName = L"Dev";

						TMap<FString, FString> testMap = connection->PsyNet->Headers->Map;

						for (int i = 0; i < testMap.Num(); i++)
						{
							Console.Write(testMap[i].Key.ToString());
							Console.Write(testMap[i].Value.ToString());

							if (testMap[i].Key == L"PsyEnvironment") {
								connection->PsyNet->Headers->Set(testMap[i].Key, L"Dev");
							}
						}

						connection->PerCon->Config->bAllowPerCon = false;
						connection->PerCon->HandleConfigChanged();
						connection->PerCon->Config->bAllowPerCon = true;
						connection->PerCon->HandleConfigChanged();
					}*/

					//UProduct_TA* product = Events.ProductDatabase->Products_New[5300];

					//if (product)
					//{
					//	product->Label = product->LongLabel = L"Rose Gold Drop";
					//	product->Quality = 4;

					//	FString ThumbnailRender = Instances.to_fstring(product->GetThumbnailAssetPath().ToString() + "Thumbnail");

					//	UTexture2D* Thumbnail = (UTexture2D*)product->DynamicLoadObject(ThumbnailRender, UTexture2D::StaticClass(), true);

					//	if (Thumbnail)
					//	{
					//		Console.Write("Found Thumbnail: " + ThumbnailRender.ToString());

					//		UTexture* CustomThumbnail = Instances.PathToTexture("Voltage\\Textures\\rose_gold_drop.png");

					//		const FPointer Save = Thumbnail->Resource;

					//		Thumbnail->Resource = CustomThumbnail->Resource;

					//		CustomThumbnail->Resource = Save;
					//	}
					//}
				}
			}
		}
	}

	void GFxSetPlayerBanner(const PostEvent& event)
	{
		UGFxData_PlayerVanity_TA* playerVanity = event.GetCaller<UGFxData_PlayerVanity_TA>();

		if (!playerVanity)
			return;

		if (Events.custombanners == true) {
			Events.playerbanner = nullptr;
			if (!Events.bannerTexture)
				Events.bannerTexture = Instances.PathToTexture("Voltage\\Textures\\Banners\\Banner.png");
			if (!Events.playerbanner)
			{
				std::vector<UGFxData_PlayerBanner_TA*> playerbanners = Instances.GetAllInstancesOf<UGFxData_PlayerBanner_TA>();
				for (UGFxData_PlayerBanner_TA* banner : playerbanners)
					if (std::to_string(banner->GetPlayerID().Uid) == Events.playerid || banner->GetPlayerID().EpicAccountId.ToString() == Events.playerid)
						Events.playerbanner = banner;
			}		
		}
		if (Events.customavatar) {
			if (!Events.online_x)
				Events.online_x = Instances.GetInstanceOf<UOnline_X>();
			if (Events.online_x->IsInMainMenu() == false) {
				if (!Events.customAvatar)
					Events.customAvatar = Instances.PathToTexture("Voltage\\Textures\\Avatar.png");
				if (Events.customAvatar) {
					if (!Events.playerAvatar) {
						if (Events.vanityManager) {
							Events.playerAvatar = Events.vanityManager->GetAvatar(Instances.GetUniqueID());
						}
					}

					if (Events.playerAvatar) {
						if (std::to_string(Events.playerAvatar->PlayerID.Uid) == Events.playerid || Events.playerAvatar->PlayerID.EpicAccountId.ToString() == Events.playerid) {
							Events.playerAvatar->HandleUpdateTexture(Events.customAvatar);
							Events.vanityManager->SetAvatar(Events.playerAvatar);

							if (!Events.dataStore)
								Events.dataStore = Instances.GetInstanceOf<UGFxDataStore_X>();
							if (Events.dataStore) {
								Events.dataStore->SetTextureValue(L"Avatars", playerVanity->GetPlayerAvatarIndex(Instances.GetUniqueID()), L"ToPlayer", Events.customAvatar);
								/*Events.dataStore->SetTextureValue(L"Avatars", playerVanity->GetPlayerAvatarIndex(Instances.GetUniqueID()), L"PaintableLayer", Events.customAvatar);
								Events.dataStore->SetTextureValue(L"Avatars", playerVanity->GetPlayerAvatarIndex(Instances.GetUniqueID()), L"TintableLayer", Events.customAvatar);*/
							}
						}
					}
				}
			}
		}
	}

	void GFxDataMainMenuAdded(PreEvent& event)
	{
		GameState.MainMenuAdded();
	}

	int rgbtoint(int r, int g, int b)
	{
		int rgb = r;
		rgb = (rgb << 8) + g;
		rgb = (rgb << 8) + b;

		return rgb;
	}

	int rgbtoint(FColor fcolor)
	{
		return rgbtoint(fcolor.R, fcolor.G, fcolor.B);
	}
}

EventsComponent::EventsComponent() : Component("Events", "Manages function hooks and process event.")
{
	OnCreate();
}

EventsComponent::~EventsComponent()
{
	OnDestroy();
}

void EventsComponent::OnCreate()
{
	Detoured = false;
	ProcessEvent = nullptr;
}

void EventsComponent::OnDestroy()
{
	DetachDetour();
}

bool EventsComponent::IsDetoured()
{
	return (Detoured && ProcessEvent);
}

void EventsComponent::AttachDetour(const ProcessEventType& detourFunction)
{
	if (!IsDetoured())
	{
		ProcessEvent = detourFunction;
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&reinterpret_cast<PVOID&>(ProcessEvent), reinterpret_cast<PVOID>(ProcessEventDetour));
		DetourTransactionCommit();
		Detoured = true;
	}
}

int currentStep = 0;

void EventsComponent::DetachDetour()
{
	if (IsDetoured())
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&reinterpret_cast<PVOID&>(ProcessEvent), reinterpret_cast<PVOID>(ProcessEventDetour));
		DetourTransactionCommit();
		Detoured = false;
		ProcessEvent = nullptr;
	}
}

void EventsComponent::ProcessEventDetour(class UObject* caller, class UFunction* function, void* params, void* result)
{
	try
	{
		if (ProcessEvent && function)
		{		
			if (caller->IsA(UWebRequest_X::StaticClass()))
			{
				UWebRequest_X* request = (UWebRequest_X*)caller;

				if (request)
				{			
					if (request->RequestState == (uint8_t)EWebRequestState::WebRequestState_PendingSend)
					{
						if (request->HTTPRequest)
						{
							// Request Sending

							std::vector<uint8_t> content1;

							for (auto& byte : request->Content)
							{
								content1.push_back(byte);
							}

							std::string str1(content1.begin(), content1.end());

							if (str1 == "")
								str1 = "{}";

							Events.psynettrafficbodies.push_back(str1);
							Events.psynettrafficlogs.push_back("Web Request: " + Instances.quote(request->URL.ToString()));

							std::string headers1;

							for (FString& header : request->HTTPRequest->GetHeaders())
							{
								headers1 = headers1 + header.ToString() + "\n";
							}

							Events.psynettrafficheaders.push_back(headers1);

							Console.WriteLog("Web Request: " + Instances.quote(request->URL.ToString()) + ": " + str1);

							Events.totalrequests++;
						}
					}
					else if (request->RequestState == (uint8_t)EWebRequestState::WebRequestState_Success)
					{
						if (request->HttpResponse)
						{
							// Response Pending

							std::vector<uint8_t> content;

							for (auto& byte : request->ResponseData)
							{
								content.push_back(byte);
							}

							std::string str(content.begin(), content.end());

							if (str == "")
								str = "{}";

							Events.psynettrafficbodies.push_back(str);
							Events.psynettrafficlogs.push_back("Web Response: " + Instances.quote(request->URL.ToString()));

							std::string headers;

							for (FString& header : request->HttpResponse->GetHeaders())
							{
								headers = headers + header.ToString() + "\n";
							}

							Events.psynettrafficheaders.push_back(headers);

							Console.WriteLog("Web Response: " + Instances.quote(request->URL.ToString()) + ": " + str);

							Events.totalrequests++;
						}
					}
				}
			}
			if (caller->IsA(APRI_TA::StaticClass()))
			{
				APRI_TA* callerPRI = (APRI_TA*)caller;

				APRI_TA_eventReplicatedEvent_Params* replicatedEventParms = (APRI_TA_eventReplicatedEvent_Params*)params;

				if (function->GetName() == "ReplicatedEvent")
				{
					if (replicatedEventParms->VarName == L"Title")
					{
						if (callerPRI)
						{
							if (callerPRI->Title == L"None")
							{
								return;
							}
						}
					}
				}
			}
			int32_t ObjectInt = function->ObjectInternalInteger;

			if (ObjectInt == NULL || ObjectInt > PostHookedEvents.max_size())
				throw std::exception(std::string("ObjectInt was NULL: " + function->GetName()).c_str());

			auto preIt = PreHookedEvents.find(ObjectInt);
			PreEvent event(caller, function, params);

			if (preIt != PreHookedEvents.end())
			{
				for (const auto& preEvent : preIt->second)
				{
					if (ObjectInt != LastPreFunction)
					{
						LastPreFunction = ObjectInt;
						preEvent(event);

						if (event.ShouldDetour())
						{
							ProcessEvent(caller, function, params, result);
						}
					}
					else
					{
						LastPreFunction = INT_MAX;
						if (event.ShouldDetour())
						{
							ProcessEvent(caller, function, params, result);
						}
					}
				}
			}
			else if (event.ShouldDetour())
			{
				ProcessEvent(caller, function, params, result);
			}

			auto postIt = PostHookedEvents.find(ObjectInt);

			if (postIt != PostHookedEvents.end())
			{
				for (const auto& postEvent : postIt->second)
				{
					if (ObjectInt != LastPostFunction)
					{
						LastPostFunction = ObjectInt;
						postEvent(PostEvent(caller, function, params, result));
					}
					else
					{
						LastPostFunction = INT_MAX;
					}
				}
			}
		}
	}

	catch (std::exception& e) { Console.Error("exception: " + (std::string)e.what()); return; }
	catch (std::exception_ptr& e) { return; }
	catch (std::runtime_error& e) { Console.Warning("runtime_error: " + (std::string)e.what()); return;}
}

bool EventsComponent::IsEventBlacklisted(uint32_t functionInteger)
{
	return (std::find(BlacklistedEvents.begin(), BlacklistedEvents.end(), functionInteger) != BlacklistedEvents.end());
}

void EventsComponent::BlacklistEvent(const std::string& function)
{
	UFunction* foundFunction = Instances.FindStaticFunction(function);

	if (foundFunction)
	{
		if (!IsEventBlacklisted(foundFunction->ObjectInternalInteger))
		{
			BlacklistedEvents.emplace_back(foundFunction->ObjectInternalInteger);
			std::sort(BlacklistedEvents.begin(), BlacklistedEvents.end());
		}
	}
	else
	{
		Console.Warning(GetNameFormatted() + "Warning: Failed to blacklist function \"" + function + "\"!");
	}
}

void EventsComponent::WhitelistEvent(const std::string& functionName)
{
	UFunction* foundFunction = Instances.FindStaticFunction(functionName);

	if (foundFunction)
	{
		std::vector<uint32_t>::iterator blackIt = std::find(BlacklistedEvents.begin(), BlacklistedEvents.end(), foundFunction->ObjectInternalInteger);

		if (blackIt != BlacklistedEvents.end())
		{
			BlacklistedEvents.erase(blackIt);
			std::sort(BlacklistedEvents.begin(), BlacklistedEvents.end());
		}
	}
	else
	{
		Console.Warning(GetNameFormatted() + "Warning: Failed to whitelist function \"" + functionName + "\"!");
	}
}

void EventsComponent::HookEventPre(const std::string& functionName, std::function<void(PreEvent&)> preHook)
{
	UFunction* foundFunction = Instances.FindStaticFunction(functionName);

	if (foundFunction)
	{
		HookEventPre(foundFunction->ObjectInternalInteger, preHook);
	}
	else
	{
		Console.Warning(GetNameFormatted() + "Warning: Failed to hook function \"" + functionName + "\"!");
	}
}

void EventsComponent::HookEventPre(uint32_t functionIndex, std::function<void(PreEvent&)> preHook)
{
	UObject* foundFunction = UObject::GObjObjects()->At(functionIndex);

	if (foundFunction && foundFunction->IsA(UFunction::StaticClass()))
	{
		if (PreHookedEvents.find(functionIndex) != PreHookedEvents.end())
		{
			PreHookedEvents[functionIndex].push_back(preHook);
		}
		else
		{
			PreHookedEvents[functionIndex] = std::vector<std::function<void(PreEvent&)>>{ preHook };
		}
	}
	else
	{
		Console.Warning(GetNameFormatted() + "Warning: Failed to hook function at index \"" + std::to_string(functionIndex) + "\"!");
	}
}

void EventsComponent::HookEventPost(const std::string& functionName, std::function<void(const PostEvent&)> postHook)
{
	UFunction* foundFunction = Instances.FindStaticFunction(functionName);

	if (foundFunction)
	{
		HookEventPost(foundFunction->ObjectInternalInteger, postHook);
	}
	else
	{
		Console.Warning(GetNameFormatted() + "Warning: Failed to hook function \"" + functionName + "\"!");
	}
}

void EventsComponent::HookEventPost(uint32_t functionIndex, std::function<void(const PostEvent&)> postHook)
{
	UObject* foundFunction = UObject::GObjObjects()->At(functionIndex);

	if (foundFunction && foundFunction->IsA(UFunction::StaticClass()))
	{
		if (PostHookedEvents.find(functionIndex) != PostHookedEvents.end())
		{
			PostHookedEvents[functionIndex].push_back(postHook);
		}
		else
		{
			PostHookedEvents[functionIndex] = std::vector<std::function<void(const PostEvent&)>>{ postHook };
		}
	}
	else
	{
		Console.Warning(GetNameFormatted() + "Warning: Failed to hook function at index \"" + std::to_string(functionIndex) + "\"!");
	}
}

void EventsComponent::UnhookEvent(const std::string& function)
{
	UFunction* foundFunction = Instances.FindStaticFunction(function);

	if (foundFunction)
	{
		int32_t functionIndex = foundFunction->ObjectInternalInteger;

		if (PostHookedEvents.find(functionIndex) != PostHookedEvents.end())
		{
			PostHookedEvents.erase(functionIndex);
		}
		if (PreHookedEvents.find(functionIndex) != PreHookedEvents.end())
		{
			PreHookedEvents.erase(functionIndex);
		}
	}
	else
	{
		Console.Warning(GetNameFormatted() + "Warning: Failed to remove hook for function \"" + function + "\"!");
	}
}

void EventsComponent::Initialize()
{
	ProductDatabase = Instances.GetInstanceOf<UProductDatabase_TA>();
	PaintDatabase = Instances.GetInstanceOf<UPaintDatabase_TA>();
	saveData = Instances.GetInstanceOf<USaveData_TA>();
	QualityAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_Quality_TA>();
	PaintedAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_Painted_TA>();
	CertifiedAttribute = Instances.GetDefaultInstanceOf<UProductAttribute_Certified_TA>();
	CertDatabase = Instances.GetInstanceOf<UCertifiedStatDatabase_TA>();
	vanityManager = Instances.GetInstanceOf<UVanitySetManager_TA>();
	blogConfig = Instances.GetInstanceOf<UBlogConfig_X>();
	iidutils = (UInstanceIDUtils_TA*)UInstanceIDUtils_TA::StaticClass();

	// Example functions only, you will need to function scan in your game for your own to hook!

	// You can hook functions like this.
	HookEventPre("Function Engine.HUD.PostRender", &Hooks::HUDPostRender);

	// Or like this, with std::bind.
	HookEventPost("Function Engine.HUD.PostRender", std::bind(&Hooks::HUDPostRenderPost, std::placeholders::_1));

	// Or even like this, with lambda expressions.
	HookEventPre("Function Engine.GameViewportClient.PostRender", [&](PreEvent& event) {
		Hooks::GameViewPortPostRender(event);
		//Console.Write("I'm a lambda function hook!");
		});

	HookEventPre("Function TAGame.MenuSequencer_TA.Tick", [&](PreEvent& event) {
		if (setcustomtitle)
		{
			if (!dataStore)
				dataStore = Instances.GetInstanceOf<UGFxDataStore_X>();

			if (dataStore)
			{
				wchar_t* p = new wchar_t[titletext.size() + 1];
				for (std::string::size_type i = 0; i < titletext.size(); ++i)
					p[i] = titletext[i];

				p[titletext.size()] = '\0';
				FString fstitletext = FString(p);

				FName t = FName(L"PlayerTitlesPlayerTitles");
				FASValue count = dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle");
				dataStore->SetStringValue(t, count.I, L"Text", fstitletext);
				FASValue fasColor = dataStore->GetValue(t, count.I, L"Color");
				fasColor.Type = 7;
				fasColor.I = titlecolor;
				FASValue fasGlowColor = dataStore->GetValue(t, count.I, L"GlowColor");
				fasGlowColor.Type = 7;
				fasGlowColor.I = titleglowcolor;
				dataStore->SetASValue(t, count.I, L"Color", fasColor);
				dataStore->SetASValue(t, count.I, L"GlowColor", fasGlowColor);
			}
		}
		if (!dataStore)
			dataStore = Instances.GetInstanceOf<UGFxDataStore_X>();
		if (dataStore) {
			FCustomTitleData customtitle = Events.hardcodedcustomtags[Events.playerid];
			if (customtitle.titletext != "") {
				if (customtitle.playerid == Events.playerid && Events.setcustomtitle == false && dopaidcustomtitle == true) {
					FName t = L"PlayerTitlesPlayerTitles";
					FASValue count = dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle");
					dataStore->SetStringValue(t, count.I, L"Text", Instances.to_fstring(customtitle.titletext));
					FASValue fasColor = dataStore->GetValue(t, count.I, L"Color");
					fasColor.Type = 7;
					fasColor.I = dataStore->FromHex(Instances.to_fstring(customtitle.titlecolor));
					FASValue fasGlowColor = dataStore->GetValue(t, count.I, L"GlowColor");
					fasGlowColor.Type = 7;
					fasGlowColor.I = dataStore->FromHex(Instances.to_fstring(customtitle.titleglow));
					dataStore->SetASValue(t, count.I, L"Color", fasColor);
					dataStore->SetASValue(t, count.I, L"GlowColor", fasGlowColor);
				}
			}
		}

		if (setcustomusername) {
			if (customusername.length() > 1) {
				if (!gfxlocalplayer)
					gfxlocalplayer = Instances.GetInstanceOf<UGFxData_LocalPlayer_TA>();
				if (gfxlocalplayer) {
					if (!dataStore)
						dataStore = Instances.GetInstanceOf<UGFxDataStore_X>();
					if (dataStore) {
						if (Format::Hex((uintptr_t)this->gfxlocalplayer, sizeof(this->gfxlocalplayer)) != "0xFFFFFFFFFFFFFECF")
							if (Instances.CompareUniqueNetId(Instances.GetUniqueID(), gfxlocalplayer->PlayerID))
								dataStore->SetStringValue(L"LocalPlayer", 0, L"PlayerName", Instances.to_fstring(customusername));
					}
				}

				if (!onlineGame)
					if (onlineGame = Instances.GetInstanceOf<UOnlineGame_X>())
						if (!onlinePlayer)
							if (onlinePlayer = onlineGame->eventGetOnlinePlayerByID(Instances.GetUniqueID()))
								onlinePlayer->SetPlayerName(Instances.to_fstring(customusername));
			}
		}
	});

	//HookEventPre("Function TAGame.PRI_TA.ReplicatedEvent", [&](PreEvent& event) {
	//	APRI_TA* callerPRI = event.GetCaller<APRI_TA>();
	//	if (callerPRI)
	//	{
	//		auto steamid = callerPRI->UniqueId.Uid;

	//		std::stringstream streamid;

	//		streamid << steamid;

	//		APRI_TA_eventReplicatedEvent_Params* replicatedEventParms = (APRI_TA_eventReplicatedEvent_Params*)event.Params();

	//		std::string Event = replicatedEventParms->VarName.ToString();

	//		if (Event == "ClientLoadouts")
	//		{
	//			if (callerPRI->UniqueId.EpicAccountId.ToString() == Events.playerid || streamid.str() == Events.playerid)
	//			{
	//				if (Events.cachedloadoutblue.Products.Num() > 1)
	//				{
	//					for (int j = 0; j < Events.cachedloadoutblue.Products.Num(); j++)
	//					{
	//						auto cachedproduct = Instances.GetProductData(Events.cachedloadoutblue.Products[j]);
	//						for (int i = 0; i < callerPRI->ClientLoadouts.Loadouts[0].Products.Num(); i++)
	//						{
	//							auto product = Instances.GetProductData(callerPRI->ClientLoadouts.Loadouts[0].Products[i]);
	//							bool sameSlot = cachedproduct.Slot == product.Slot;

	//							if (sameSlot || cachedproduct.GetID() != 0)
	//							{
	//								memcpy_s(&callerPRI->ClientLoadouts.Loadouts[0].Products[i], sizeof(int32_t), &Events.cachedloadoutblue.Products[j], sizeof(int32_t));
	//							}
	//						}
	//					}
	//				}
	//				if (Events.cachedloadoutorange.Products.Num() > 1)
	//				{
	//					for (int j = 0; j < Events.cachedloadoutorange.Products.Num(); j++)
	//					{
	//						auto cachedproduct = Instances.GetProductData(Events.cachedloadoutorange.Products[j]);
	//						for (int i = 0; i < callerPRI->ClientLoadouts.Loadouts[1].Products.Num(); i++)
	//						{
	//							auto product = Instances.GetProductData(callerPRI->ClientLoadouts.Loadouts[1].Products[i]);
	//							bool sameSlot = cachedproduct.Slot == product.Slot;

	//							if (sameSlot || cachedproduct.GetID() != 0)
	//							{
	//								memcpy_s(&callerPRI->ClientLoadouts.Loadouts[1].Products[i], sizeof(int32_t), &Events.cachedloadoutorange.Products[j], sizeof(int32_t));
	//							}
	//						}
	//					}
	//				}
	//			}
	//		}		
	//	}
	//});

	HookEventPre("Function TAGame.GFxHUD_TA.Tick", [&](PreEvent& event) {
		if (!dataStore)
			dataStore = Instances.GetInstanceOf<UGFxDataStore_X>();

		if (!skillz)
			skillz = Instances.GetInstanceOf<UOnlineGameSkill_X>();

		AGFxHUD_TA* hud = event.GetCaller<AGFxHUD_TA>();

		FUniqueNetId NetId = Instances.GetUniqueID();

		if (!localplayerpri)
		{
			localplayerpri = hud->GetPRIDataFromID(NetId);
			teamindex = localplayerpri->Team;
		}
		if (!localplayerpri)
			return;

		AGameEvent_TA* gameEvent = hud->GetGameEvent();

		if (gameEvent)
		{
			AGameEvent_Soccar_TA* soccarEvent = (AGameEvent_Soccar_TA*)gameEvent;

			if (soccarEvent)
			{
				if (soccarEvent->Teams.Num() == 0)
					return;

				if (&soccarEvent->Teams == nullptr)
					return;

				ATeam_TA* blueteam = soccarEvent->Teams[0];
				ATeam_TA* orangeteam = soccarEvent->Teams[1];

				if (!orangeteam || !blueteam)
					return;

				if (Events.defaultorangeteamcolors == true) {
					TArray<FLinearColor> colorList;
					colorList.Add(orangeteam->ColorToLinearColor(FColor{ 24,115,255 }));
					orangeteam->UpdateGameShaderParamColors(1, colorList);
				}
				if (Events.defaultblueteamcolors == true) {
					TArray<FLinearColor> colorList;
					colorList.Add(blueteam->ColorToLinearColor(FColor{ 193,100,24 }));
					blueteam->UpdateGameShaderParamColors(0, colorList);
				}

				if (Events.custombluecolors == true) {
					TArray<FLinearColor> colorList;
					colorList.Add(FLinearColor{ Events.blueteamcolor[0], Events.blueteamcolor[1], Events.blueteamcolor[2] });
					blueteam->UpdateGameShaderParamColors(0, colorList);
				}
				if (Events.customorangecolors == true) {
					TArray<FLinearColor> colorList;
					colorList.Add(FLinearColor{ Events.orangeteamcolor[0], Events.orangeteamcolor[1], Events.orangeteamcolor[2] });
					orangeteam->UpdateGameShaderParamColors(1, colorList);
				}
				if (Events.rgbteamcolors == true) {
					TArray<FLinearColor> colorList;
					colorList.Add(FRainbowColor::GetLinear().UnrealColor());
					blueteam->UpdateGameShaderParamColors(0, colorList);
					orangeteam->UpdateGameShaderParamColors(1, colorList);
				}
			}
		}	

		if (Events.dataStore) {
			int blueIndex = 0;
			int orangeIndex = 1;

			FASValue value;
			value.Type = 7;

			if (Events.GFXcustomorangecolor) {
				value.I = Colors::LinearToDecimal(FLinearColor{ Events.GFXcustomorangecolors[0], Events.GFXcustomorangecolors[1], Events.GFXcustomorangecolors[2] });
				Events.dataStore->SetASValue(L"TeamInfo", orangeIndex, L"TeamColor", value);
			}
			else if (Events.GFXcustombluecolor) {
				value.I = Colors::LinearToDecimal(FLinearColor{ Events.GFXcustombluecolors[0], Events.GFXcustombluecolors[1], Events.GFXcustombluecolors[2] });
				Events.dataStore->SetASValue(L"TeamInfo", blueIndex, L"TeamColor", value);
			}
			else if (Events.GFXdefaultorangeteamcolors) {
				value.I = Colors::ColorToDecimal(FColor{ 24,115,255 });
				Events.dataStore->SetASValue(L"TeamInfo", orangeIndex, L"TeamColor", value);
			}
			else if (Events.GFXdefaultblueteamcolors) {
				value.I = Colors::ColorToDecimal(FColor{ 193,100,24 });
				Events.dataStore->SetASValue(L"TeamInfo", blueIndex, L"TeamColor", value);
			}
			else if (Events.GFXrgbteamcolors) {
				value.I = FRainbowColor::GetDecimal();
				Events.dataStore->SetASValue(L"TeamInfo", blueIndex, L"TeamColor", value);
				Events.dataStore->SetASValue(L"TeamInfo", orangeIndex, L"TeamColor", value);
			}
		}

		for (UGFxData_PRI_TA* pri : hud->PRIData) {
			Events.hud = hud;
			std::string playerId = pri->PlayerID.EpicAccountId.ToString();
			if (playerId == Events.playerid || std::to_string(pri->PlayerID.Uid) == Events.playerid) {

				if (setcustomusername) {
					if (customusername.length() > 1) {
						pri->Persona->SetPlayerName(Instances.to_fstring(customusername));
						if (!gfxlocalplayer)
							gfxlocalplayer = Instances.GetInstanceOf<UGFxData_LocalPlayer_TA>();
						if (gfxlocalplayer) {
							if (!dataStore)
								dataStore = Instances.GetInstanceOf<UGFxDataStore_X>();
							if (dataStore) {
								playerId = gfxlocalplayer->PlayerID.EpicAccountId.ToString();
								if (playerId == Events.playerid || std::to_string(gfxlocalplayer->PlayerID.Uid) == Events.playerid)
									dataStore->SetStringValue(gfxlocalplayer->TableName, gfxlocalplayer->RowIndex, L"PlayerName", Instances.to_fstring(customusername));
							}
						}
					}
				}
			}

			FCustomTitleData customtitle;

			if (pri->PlayerID.Platform == 11)
				customtitle = Events.hardcodedcustomtags[pri->PlayerID.EpicAccountId.ToString()];
			else
				customtitle = Events.hardcodedcustomtags[std::to_string(pri->PlayerID.Uid)];

			if (pri->PlayerID.EpicAccountId.ToString() == customtitle.playerid || std::to_string(pri->PlayerID.Uid) == customtitle.playerid) {

				if (customtitle.playerid == Events.playerid) {
					if (setcustomtitle == false && dopaidcustomtitle == true) {
						FName t = L"PlayerInfo";
						dataStore->SetStringValue(t, pri->RowIndex, L"XPTitle", Instances.to_fstring(customtitle.titletext));
						FASValue fasColor = dataStore->GetValue(t, pri->RowIndex, L"TitleColor");
						fasColor.Type = 7;
						fasColor.I = pri->FromHex(Instances.to_fstring(customtitle.titlecolor));
						FASValue fasGlowColor = dataStore->GetValue(t, pri->RowIndex, L"TitleGlowColor");
						fasGlowColor.Type = 7;
						fasGlowColor.I = pri->FromHex(Instances.to_fstring(customtitle.titleglow));
						dataStore->SetASValue(t, pri->RowIndex, L"TitleColor", fasColor);
						dataStore->SetASValue(t, pri->RowIndex, L"TitleGlowColor", fasGlowColor);

						if (setcustomtitle == false && dopaidcustomtitle == true) {
							FName t = FName(L"PlayerTitlesPlayerTitles");
							FASValue count = dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle");
							dataStore->SetStringValue(t, count.I, L"Text", Instances.to_fstring(customtitle.titletext));
							FASValue fasColor = dataStore->GetValue(t, count.I, L"Color");
							fasColor.Type = 7;
							fasColor.I = dataStore->FromHex(Instances.to_fstring(customtitle.titlecolor));
							FASValue fasGlowColor = dataStore->GetValue(t, count.I, L"GlowColor");
							fasGlowColor.Type = 7;
							fasGlowColor.I = dataStore->FromHex(Instances.to_fstring(customtitle.titleglow));
							dataStore->SetASValue(t, count.I, L"Color", fasColor);
							dataStore->SetASValue(t, count.I, L"GlowColor", fasGlowColor);
						}
					}
				}
				else {
					FName t = L"PlayerInfo";
					dataStore->SetStringValue(t, pri->RowIndex, L"XPTitle", Instances.to_fstring(customtitle.titletext));
					FASValue fasColor = dataStore->GetValue(t, pri->RowIndex, L"TitleColor");
					fasColor.Type = 7;
					fasColor.I = pri->FromHex(Instances.to_fstring(customtitle.titlecolor));
					FASValue fasGlowColor = dataStore->GetValue(t, pri->RowIndex, L"TitleGlowColor");
					fasGlowColor.Type = 7;
					fasGlowColor.I = pri->FromHex(Instances.to_fstring(customtitle.titleglow));
					dataStore->SetASValue(t, pri->RowIndex, L"TitleColor", fasColor);
					dataStore->SetASValue(t, pri->RowIndex, L"TitleGlowColor", fasGlowColor);
				}
			}
		}
		if (setcustomtitle)
		{
			if (hud && dataStore)
			{
				FUniqueNetId NetID = Instances.GetUniqueID();

				UGFxData_PRI_TA* localplayerpri = hud->GetPRIDataFromID(NetID);

				if (localplayerpri)
				{
					wchar_t* p = new wchar_t[titletext.size() + 1];
					for (std::string::size_type i = 0; i < titletext.size(); ++i)
						p[i] = titletext[i];

					p[titletext.size()] = '\0';
					FString fstitletext = FString(p);

					FName t = L"PlayerInfo";
					dataStore->SetStringValue(t, localplayerpri->RowIndex, L"XPTitle", fstitletext);
					FASValue fasColor = dataStore->GetValue(t, localplayerpri->RowIndex, L"TitleColor");
					fasColor.Type = 7;
					fasColor.I = titlecolor;
					FASValue fasGlowColor = dataStore->GetValue(t, localplayerpri->RowIndex, L"TitleGlowColor");
					fasGlowColor.Type = 7;
					fasGlowColor.I = titleglowcolor;
					dataStore->SetASValue(t, localplayerpri->RowIndex, L"TitleColor", fasColor);
					dataStore->SetASValue(t, localplayerpri->RowIndex, L"TitleGlowColor", fasGlowColor);
				}
			}
			wchar_t* p = new wchar_t[titletext.size() + 1];
			for (std::string::size_type i = 0; i < titletext.size(); ++i)
				p[i] = titletext[i];

			p[titletext.size()] = '\0';
			FString fstitletext = FString(p);

			FName t = FName(L"PlayerTitlesPlayerTitles");
			FASValue count = dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle");
			dataStore->SetStringValue(t, count.I, L"Text", fstitletext);
			FASValue fasColor = dataStore->GetValue(t, count.I, L"Color");
			fasColor.Type = 7;
			fasColor.I = titlecolor;
			FASValue fasGlowColor = dataStore->GetValue(t, count.I, L"GlowColor");
			fasGlowColor.Type = 7;
			fasGlowColor.I = titleglowcolor;
			dataStore->SetASValue(t, count.I, L"Color", fasColor);
			dataStore->SetASValue(t, count.I, L"GlowColor", fasGlowColor);
		}
		else {
			
			/*AGFxHUD_TA* hud = static_cast<AGFxHUD_TA*>(event.Caller());

			if (hud && dataStore)
			{
				FUniqueNetId NetID = Instances.GetUniqueID();

				UGFxData_PRI_TA* myplri = hud->GetPRIDataFromID(NetID);

				if (myplri)
				{
					FString titletext = dataStore->GetValue(L"PlayerTitlesPlayerTitles", dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle").I, L"Text").S;
					int titlecolor = dataStore->GetValue(L"PlayerTitlesPlayerTitles", dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle").I, L"Color").I;
					int titleglowcolor = dataStore->GetValue(L"PlayerTitlesPlayerTitles", dataStore->GetValue(L"PlayerTitles", NULL, L"SelectedTitle").I, L"GlowColor").I;
					if (titletext.ToString() != "null") {
						FName t = L"PlayerInfo";
						dataStore->SetStringValue(t, myplri->RowIndex, L"XPTitle", titletext);
						FASValue fasColor = dataStore->GetValue(t, myplri->RowIndex, L"TitleColor");
						fasColor.Type = 7;
						fasColor.I = titlecolor;
						FASValue fasGlowColor = dataStore->GetValue(t, myplri->RowIndex, L"TitleGlowColor");
						fasGlowColor.Type = 7;
						fasGlowColor.I = titleglowcolor;
						dataStore->SetASValue(t, myplri->RowIndex, L"TitleColor", fasColor);
						dataStore->SetASValue(t, myplri->RowIndex, L"TitleGlowColor", fasGlowColor);
					}
				}
			}*/
		}
	});

	//HookEventPre("Function TAGame.PRI_TA.ReplicatedEvent", [&](PreEvent& event) {
	//	APRI_TA_eventReplicatedEvent_Params* Params = event.GetParams<APRI_TA_eventReplicatedEvent_Params>();
	//	APRI_TA* Pri = event.GetCaller<APRI_TA>();

	//	if (Params && Pri)
	//	{
	//		if (Params->VarName.ToString() == "ClientLoadouts")
	//		{
	//			for (int i = 0; i < Pri->ClientLoadouts.Loadouts[0].Products.Num(); i++)
	//			{
	//				UProduct_TA* Product = Events.ProductDatabase->Products_New[Pri->ClientLoadouts.Loadouts[0].Products[i]];

	//				if (Product)
	//				{
	//					if (Product->Slot->SlotIndex == Events.boostIndex)
	//					{
	//						int PinkStandard = 65;

	//						memcpy_s(&Pri->ClientLoadouts.Loadouts[0].Products[i], sizeof(int), &PinkStandard, sizeof(int));
	//					}
	//				}
	//			}

	//			for (int i = 0; i < Pri->ClientLoadouts.Loadouts[1].Products.Num(); i++)
	//			{
	//				UProduct_TA* Product = Events.ProductDatabase->Products_New[Pri->ClientLoadouts.Loadouts[1].Products[i]];

	//				if (Product)
	//				{
	//					if (Product->Slot->SlotIndex == Events.boostIndex)
	//					{
	//						int PinkStandard = 65;

	//						memcpy_s(&Pri->ClientLoadouts.Loadouts[1].Products[i], sizeof(int), &PinkStandard, sizeof(int));
	//					}
	//				}
	//			}
	//		}
	//	}
	//});

	HookEventPre("Function ProjectX.RPCQueue_X.CreateBatchSingleRPC", [&](PreEvent& event) 
		{
			URPCQueue_X_eventCreateBatchSingleRPC_Params* RequestMessageParams = (URPCQueue_X_eventCreateBatchSingleRPC_Params*)event.Params();
			if (RequestMessageParams)
			{
				if (RequestMessageParams->Message->Headers) {
					UPsyNetMessage_X* RequestMessage = RequestMessageParams->Message;

					if (RequestMessage) {
						Events.CurrentRequest = RequestMessageParams;
						TMap<FString, FString> requestMap = RequestMessage->Headers->Map;
	
						json bodyjson;
						std::string psyservice;
						try {
							psyservice = requestMap[L"PsyService"].ToString();

							if (psyservice.find("DSR"))
								bodyjson = json::parse(RequestMessage->GetBodyText().ToString());
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

						std::string folder_path = "Voltage\\Plugins\\";

						for (const auto& entry : std::filesystem::directory_iterator(folder_path))
						{
							if (entry.path().extension() == ".json")
							{
								std::ifstream input_file(entry.path());
								std::string input = std::string((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());

								// Replace occurrences of "geniid" and "timestamp" in input with corresponding values
								Instances.ReplaceString(input, "geniid", Instances.GeneratePIIDstr());
								Instances.ReplaceString(input, "timestamp", Instances.GetTimestampStr());
								Instances.ReplaceString(input, "delete,", "\"delete\",");
								Instances.ReplaceString(input, "playerid", std::string(Events.platform == 1 ? "Steam|" : 2 ? "Epic|" : "") + Events.playerid + "|0");

								json pluginjson;

								try {
									if (Instances.is_valid_json(input))
									{
										pluginjson = json::parse(input);

										if (psyservice.find(pluginjson["Pattern"].get<std::string>()) != std::string::npos)
										{
											if (pluginjson.contains("Outgoing"))
											{
												for (auto& [key, value] : bodyjson.items()) {
													auto it = pluginjson["Outgoing"].find(key);
													if (it != pluginjson["Outgoing"].end()) {
														if (it.value() == "delete") {
															auto it2 = pluginjson["Outgoing"].find(key);
															if (it2 == pluginjson["Outgoing"].end()) {
																value = it2.value();
															}
															else {
																bodyjson.erase(key);
															}
														}
														else {
															value = it.value();
														}
													}
												}

												for (auto& [key, value] : pluginjson["Outgoing"].items()) {
													auto it = bodyjson.find(key);
													if (it == bodyjson.end() && value != "delete") {
														bodyjson[key] = value;
													}
												}

												Console.Notify("Modifying Outgoing: " + psyservice + "\nBody: " + bodyjson.dump(4));
											}
										}
									}
									else
									{	
										throw std::exception(std::string("Invalid JSON: " + input).c_str());
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
							}
						}

						//if (psyservice == "Metrics/RecordMetrics v1")
						//{
						//	UEventRecorderConfig_X* eventRecorder = Instances.GetInstanceOf<UEventRecorderConfig_X>();

						//	if (eventRecorder)
						//	{
						//		eventRecorder->bEnabled = false;
						//		eventRecorder->Apply();
						//	}

						//	UServerConfig_X* serverConfig = Instances.GetInstanceOf<UServerConfig_X>();

						//	if (serverConfig)
						//	{
						//		serverConfig->bUploadLogFiles = false;
						//		serverConfig->bUploadReplays = false;
						//		serverConfig->Apply();
						//	}

						//	bodyjson = {};
						//	RequestMessageParams->RPC.NextSendTime = MAXINT32;
						//}

						if (psyservice == "Products/GetPlayerProducts v2") 
						{
							if (Events.disableinventorysyncs)
								bodyjson.erase("PlayerID");
						}

						if (psyservice == "Filters/FilterContent v1") {
							std::string contentToFilter = bodyjson["Content"].dump();
							Instances.ReplaceString(contentToFilter, "\"", "");
							Instances.ReplaceString(contentToFilter, "[", "");
							Instances.ReplaceString(contentToFilter, "]", "");
							Events.filtercontent.push_back(contentToFilter);
						}

						if (psyservice == "DSR/RelayToServer v1") {

							/*garageGFX = Instances.GetInstanceOf<UGFxData_Garage_TA>();
							if (garageGFX) {
								UCarPreviewSet_TA* previewSet = garageGFX->CarPreviewSet;
								if (previewSet) {
									const int original = previewactor->PreviewTeam;
									Events.cachedloadoutblue.Products.Clear();
									Events.cachedloadoutorange.Products.Clear();

									ACarPreviewActor_TA* carPreview = previewSet->GetPlayerCarPreviewActor(Instances.IULocalPlayer());
									if (carPreview)
									{
											garageGFX->SetPreviewTeam(0);
											for (int32_t& pID : carPreview->Loadout.Products)
											{
												Events.cachedloadoutblue.Products.Add(pID);

											}
											garageGFX->SetPreviewTeam(1);
											for (int32_t& pID : carPreview->Loadout.Products)
											{
												Events.cachedloadoutorange.Products.Add(pID);

											}
											garageGFX->SetPreviewTeam(original);
									}
								}
							}*/
							/*std::string decode = bodyjson["MessagePayload"].get<std::string>();

							Instances.ReplaceString(decode, "\\\"", "\"");

							json decodejson = json::parse(decode);

							for (json player : decodejson["Players"])
							{
								if (player["PlayerID"].get<std::string>().find(Events.playerid) != std::string::npos)
								{
									std::vector<int> Loadout = player["Loadout"].get<std::vector<int>>();

									Events.cachedloadoutblue.Clear();
									Events.cachedloadoutorange.Clear();

									for (int& product : Loadout)
									{
										Events.cachedloadoutblue.Add(product);
										Events.cachedloadoutorange.Add(product);
									}
								}
							}*/

							if (Events.setcustomusername) {
								UOnlineGame_X* onlineGame = Instances.GetInstanceOf<UOnlineGame_X>();
								FUniqueNetId playerID = Instances.GetUniqueID();
								if (onlineGame)
								{
									UOnlinePlayer_X* player = onlineGame->eventGetOnlinePlayerByID(playerID);

									if (player)
										player->SetPlayerName(Instances.to_fstring(Events.customusername));
								}
							}
							//Events.relayBody = RequestMessage->GetBodyText().ToString();
						}

						if (psyservice == "Products/UnlockContainer v2") {
							URPC_MicroTransactions_UnlockContainer_TA* unlockcontainer = (URPC_MicroTransactions_UnlockContainer_TA*)RequestMessageParams->RPC.RPC;
							if (unlockcontainer) {
								for (FProductInstanceID& iid : unlockcontainer->InstanceIDs) {
									if (Events.saveData) {
										UOnlineProduct_TA* product = Events.saveData->GetOnlineProduct(iid);
										if (product) {
											Events.whichcrateiopened = product->ProductID;
											if (product->ProductID == 5298) {
												Events.openedblackmarketdrop = true;
												//	Console.Write("BM Drop");
											}
											if (product->ProductID == 5299) {
												Events.openedexoticdrop = true;
												//	Console.Write("EXO Drop");
											}
											if (product->ProductID == 5300) {
												Events.openedimportdrop = true;
												//	Console.Write("IMP Drop");
											}
											if (product->ProductID == 3011) {
												Events.openedbeachdrop = true;
												//	Console.Write("BEACH Drop");
											}
											if (product->ProductID == 2445) {
												Events.openedhallowdrop = true;
												//	Console.Write("HALLOW Drop");
											}
											if (product->ProductID == 2522) {
												Events.openedsantadrop = true;
												//	Console.Write("SANTA Drop");
											}
											if (product->ProductID == 2731) {
												Events.openedspringdrop = true;
												//	Console.Write("SPRING Drop");
											}
											if (product->ProductID == 4722) {
												Events.openedbonusgiftdrop = true;
												//	Console.Write("BONUSGIFT Drop");
											}
											if (product->ProductID == 5085) {
												Events.openedprospectdrop = true;
											}
										}
									}
								}
							}
						}
						if (psyservice == "Codes/RedeemCode v2") {
							URPC_RedeemCode_TA* redeemrpc = (URPC_RedeemCode_TA*)RequestMessageParams->RPC.RPC;
							if (redeemrpc) {
								Events.usedredeemcode = redeemrpc->Code.ToString();
							}
						}
						if (psyservice.find("Shops/PurchaseItemFromShop") != std::string::npos)
						{
							if (bodyjson["ShopID"] == 55)
							{
								int costID = bodyjson["ShopItemCostID"].get<int>();

								switch (costID) {
									case 14666:
										Events.cupopened_prospect = true;
									case 14667:
										Events.cupopened_challengers = true;
									case 14668:
										Events.cupopened_allstars = true;
									case 14669:
										Events.cupopened_champions = true;
								}
							}
						}

						if (psyservice.find("DSR"))
						{
							RequestMessage->SetBodyText(Instances.to_fstring(bodyjson.dump()));

							const std::string key = "c338bd36fb8c42b1a431d30add939fc7";
							const std::string data = "-" + RequestMessage->GetBodyText().ToString();

							std::vector<uint8_t> NewPsySigVec(SHA256_HASH_SIZE);

							hmac_sha256(key.data(), key.size(), data.data(), data.size(), NewPsySigVec.data(), NewPsySigVec.size());

							std::stringstream ss_result;
							for (uint8_t x : NewPsySigVec) {
								ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
							}

							std::string NewPsySig(Instances.convert_to_base64((char*)ss_result.str().c_str()));

							RequestMessage->Headers->Set(L"PsySig", Instances.to_fstring(NewPsySig));
						}

						Events.psynettrafficlogs.push_back("Request: " + Instances.quote(psyservice));
						Console.WriteLog("Outgoing Request: " + Instances.quote(psyservice) + " " + RequestMessage->GetBodyText().ToString());
						Events.psynettrafficbodies.push_back(RequestMessage->GetBodyText().ToString());
						
						Events.totalrequests = Events.psynettrafficlogs.size();
					}
				}
			}
	});

	HookEventPost("Function ProjectX.RPCQueue_X.CreateBatchSingleRPC", [&](const PostEvent& event) 
	{
			URPCQueue_X_eventCreateBatchSingleRPC_Params* RequestMessageParams = (URPCQueue_X_eventCreateBatchSingleRPC_Params*)event.Params();
			if (RequestMessageParams) {
				UPsyNetMessage_X* RequestMessage = RequestMessageParams->Message;
				if (RequestMessage)
				{
					if (RequestMessage->Headers)
					{
						Events.CurrentRequest = RequestMessageParams;
						TMap<FString, FString> requestMap = RequestMessage->Headers->Map;

						std::string psyservice = RequestMessage->Headers->Get(L"PsyRequestID").ToString();
						std::string requestid = RequestMessage->Headers->Get(L"PsyService").ToString();
						std::string headers = "None Found";

						for (int i = 0; i < requestMap.Num(); i++) 
						{
							Instances.ReplaceString(headers, "None Found", "");

							if (requestMap.At(i).Key.IsValid() && requestMap.At(i).Value.IsValid())
								headers = headers + requestMap.At(i).Key.ToString() + ": " + requestMap.At(i).Value.ToString() + "\n";
						}

						if (headers != "None Found") 
						{
							Events.psynettrafficheaders.push_back(headers);
							Events.PsyNetMessages.emplace(psyservice, requestid);
						}
					}
				}
			}
	});

	Instances.sendAPIRequest((URPC_MicroTransactions_GetContainerDropTable_TA*)URPC_MicroTransactions_GetContainerDropTable_TA::StaticClass());
	HookEventPre("Function ProjectX.PsyNetMessenger_X.EventMessageReceived", [&](PreEvent& event) 
	{
			UPsyNetMessenger_X_execEventMessageReceived_Params* responseRequestMessage = (UPsyNetMessenger_X_execEventMessageReceived_Params*)event.Params();

			if (responseRequestMessage)
			{
				if (responseRequestMessage->Message && responseRequestMessage->Message->Headers)
				{
					Events.CurrentResponse = responseRequestMessage;
					Events.Responses++;

					TMap<FString, FString> requestResponseMap = responseRequestMessage->Message->Headers->Map;
					std::string psyservice = "Not Found";
					std::string responseid = "Not Found";
					std::string psytime = ""/*"0"*/;

					try {
						for (int i = 0; i < requestResponseMap.Num(); i++)
						{
							if (requestResponseMap.At(i).Key.ToString() == "PsyTime")
							{
								psytime = requestResponseMap.At(i).Value.ToString();
							}

							else if (requestResponseMap.At(i).Key.ToString() == "PsyResponseID")
							{
								responseid = requestResponseMap.At(i).Value.ToString();
								psyservice = Events.PsyNetMessages.find(responseid)->second;

								if (Events.PsyNetMessages.find(responseid)._Ptr)
									Events.PsyNetMessages.erase(responseid);
							}

							else if (requestResponseMap.At(i).Key.ToString() == "PsyService")
							{
								psyservice = "SERVICE" + requestResponseMap[L"PsyService"].ToString() + " v" + requestResponseMap[L"PsyServiceVersion"].ToString();
							}
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

					std::string folder_path = "Voltage\\Plugins\\";
					json bodyjson;

					for (const auto& entry : std::filesystem::directory_iterator(folder_path))
					{
						if (entry.path().extension() == ".json")
						{
							std::ifstream input_file(entry.path());
							std::string input = std::string((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());

							// Replace occurrences of "geniid" and "timestamp" in input with corresponding values
							Instances.ReplaceString(input, "geniid", Instances.GeneratePIIDstr());
							Instances.ReplaceString(input, "timestamp", psytime);
							Instances.ReplaceString(input, "delete,", "\"delete\",");
							Instances.ReplaceString(input, "playerid", std::string(Events.platform == 1 ? "Steam|" : 2 ? "Epic|" : "") + Events.playerid + "|0");

							json pluginjson;

							try {
								if (Instances.is_valid_json(input))
								{
									pluginjson = json::parse(input);
									if (Instances.is_valid_json(responseRequestMessage->Message->GetBodyText().ToString()))
									{
										bodyjson = json::parse(responseRequestMessage->Message->GetBodyText().ToString());

										if (psyservice.find(pluginjson["Pattern"].get<std::string>()) != std::string::npos)
										{
											if (pluginjson.contains("Incoming"))
											{
												for (auto& [key, value] : bodyjson.items()) {
													auto it = pluginjson["Incoming"].find(key);
													if (it != pluginjson["Incoming"].end()) {
														if (it.value() == "delete") {
															auto it2 = pluginjson["Incoming"].find(key);
															if (it2 == pluginjson["Incoming"].end()) {
																value = it2.value();
															}
															else {
																bodyjson.erase(key);
															}	
														}
														else {
															value = it.value();
														}
													}
												}

												for (auto& [key, value] : pluginjson["Incoming"].items()) {
													auto it = bodyjson.find(key);
													if (it == bodyjson.end() && value != "delete") {
														bodyjson[key] = value;
													}
												}

												Console.Notify("Modifying Incoming: " + psyservice + "\nBody: " + bodyjson.dump(4));

												responseRequestMessage->Message->SetBodyText(Instances.to_fstring(bodyjson.dump()));
											}
										}
									}
								}
								else
								{
									throw std::exception(std::string("Invalid JSON: " + input).c_str());
								}
							}

							catch (json::exception& e) { Console.Error(e.what()); }
							catch (std::exception& e) { Console.Error(e.what()); }
						}
					}

					if (psyservice == "Products/GetContainerDropTable v2") {
						json catalogbody = json::parse(responseRequestMessage->Message->GetBodyText().ToString());
						//json customcrate;
						//customcrate["ProductID"] = 8414;
						//customcrate["SeriesID"] = 0;
						//for (SProductData& product : Events.ProductsForImGui)
						//{
						//	if (product.GetQuality() == 8) {

						//		json customdrop;

						//		customdrop["ProductID"] = product.GetID();
						//		customdrop["InstanceID"] = NULL;
						//		customdrop["Attributes"] = std::vector<json>{};
						//		customdrop["SeriesID"] = 0;
						//		customdrop["AddedTimestamp"] = NULL;
						//		customdrop["UpdatedTimestamp"] = NULL;

						//		customcrate["Drops"].push_back(customdrop);
						//	}
						//}
						//catalogbody["Result"]["ContainerDrops"].push_back(customcrate);

						/*for (json& container : catalogbody["Result"]["ContainerDrops"])
						{
							if (container["ProductID"].get<int>() == 5300)
							{
								container["Drops"].clear();

								std::vector<int> golditems{ 23, 4284, 4770, 402, 5188, 1661, 1580, 376, 822, 731, 1581, 1905, 8493, 1907, 2023, 2702, 2817, 3703, 36, 45, 53, 63, 1092, 1552, 1553, 1565 };

								for (int& product : golditems)
								{
									json customdrop;

									customdrop["ProductID"] = product;
									customdrop["InstanceID"] = NULL;
									customdrop["Attributes"] = std::vector<json>{};
									json attribute1;
									attribute1["Key"] = "Painted";
									attribute1["Value"] = "15";
									customdrop["Attributes"].push_back(attribute1);
									if (product == 35 || product == 36 || product == 45 || product == 52 || product == 44 || product == 62 || product == 63 || product == 53 || product == 23 || product == 22 || product == 30 || product == 25 || product == 31 || product == 28)
									{
										json attribute;
										attribute["Key"] = "Quality";
										attribute["Value"] = "Import";
										customdrop["Attributes"].push_back(attribute);
									}
									if (product == 376) 
										{
										json attribute;
										attribute["Key"] = "Quality";
										attribute["Value"] = "VeryRare";
										customdrop["Attributes"].push_back(attribute);
									}
									customdrop["SeriesID"] = container["SeriesID"];
									customdrop["AddedTimestamp"] = NULL;
									customdrop["UpdatedTimestamp"] = NULL;

									container["Drops"].push_back(customdrop);
								}
							}
						}*/
						std::string catalogstr = catalogbody.dump();
						FString catalogfstr = Instances.to_fstring(catalogstr);
						responseRequestMessage->Message->SetBodyText(catalogfstr);
						Events.CatalogJSON = responseRequestMessage->Message->GetBodyText().ToString();
					}

					else if (psyservice == "Codes/RedeemCode v2") {
						std::string input;
						std::string newbody;
						std::string productID;
						std::string instanceID;

						// Check the redeemed code so we can decide which item to give the player
						if (Events.usedredeemcode == "!voltage") {
							// Read contents of customredeemcodes.txt into input variable
							std::ifstream input_file("customredeemcodes.txt");
							input = std::string((std::istreambuf_iterator<char>(input_file)), std::istreambuf_iterator<char>());

							// Replace occurrences of "geniid" and "psytime" in input with corresponding values
							Instances.ReplaceString(input, "geniid", Instances.GeneratePIIDstr());
							Instances.ReplaceString(input, "psytime", psytime);

							// Set body text of response message to modified input string
							responseRequestMessage->Message->SetBodyText(Instances.to_fstring(Instances.RemoveSpaces(input)));
						}
						else if (Events.usedredeemcode == "PSYONIXSECRETTEST2314") {
							// Set productID and instanceID variables
							productID = "1332";
							instanceID = Instances.GeneratePIIDstr(1332);

							// Build newbody string using string concatenation
							newbody = "{\"Result\":{\"Drops\":[{\"ProductID\":\"" + productID + "\",\"InstanceID\":\"" + instanceID + "\",\"Attributes\":[{\"Key\":\"Painted\",\"Value\":\"14\"},{\"Key\":\"RentalLength\",\"Value\":\"69420\"},{\"Key\":\"Quality\",\"Value\":\"BlackMarket\"},{\"Key\":\"Certified\",\"Value\":\"13\"}],\"SeriesID\":0,\"AddedTimestamp\":" + requestResponseMap[L"PsyTime"].ToString() + ",\"UpdatedTimestamp\":" + requestResponseMap[L"PsyTime"].ToString() + "}]}}";

							// Set body text of response message to newbody string
							responseRequestMessage->Message->SetBodyText(Instances.to_fstring(newbody));
						}
						else if (Events.usedredeemcode == "!AlphaBoostSpawn(Dev_ID83678_DEVIN)") {
							// Set productID and instanceID variables
							productID = "32";
							instanceID = Instances.GeneratePIIDstr(32);

							// Build newbody string using string concatenation
							newbody = "{\"Result\":{\"Drops\":[{\"ProductID\":\"" + productID + "\",\"InstanceID\":\"" + instanceID + "\",\"Attributes\":[],\"SeriesID\":0,\"AddedTimestamp\":" + requestResponseMap[L"PsyTime"].ToString() + ",\"UpdatedTimestamp\":" + requestResponseMap[L"PsyTime"].ToString() + "}]}}";

							// Set body text of response message to newbody string
							responseRequestMessage->Message->SetBodyText(Instances.to_fstring(newbody));
						}
					}

					if (psyservice.find("Shops/PurchaseItemFromShop") != std::string::npos)
					{
						json BodyJson = json::parse(responseRequestMessage->Message->GetBodyText().ToString());

						if (BodyJson["Error"]["Type"] == "ShopNotEnoughCurrency")
						{
							BodyJson.clear();

							if (Events.cupopened_allstars || Events.cupopened_challengers || Events.cupopened_prospect)
							{
								srand(std::chrono::system_clock::now().time_since_epoch().count());

								int quality = -1;
								int seriesId = 0;
								Events.crateitem = 0;
								Events.crateitem_cert = 0;
								Events.crateitem_paint = 0;

								try {
									if (Events.CatalogJSON.length() < 3) {
										if (Events.CatalogJSON.length() < 3)
										{
											URPC_MicroTransactions_GetContainerDropTable_TA* getcatalog = Instances.CreateInstance<URPC_MicroTransactions_GetContainerDropTable_TA>();
											if (getcatalog)
												Instances.sendAPIRequest(getcatalog);
										}
										return;
									}

									std::vector<int> CrateItems;

									json Catalog = json::parse(Events.CatalogJSON)["Result"]["ContainerDrops"];

									// Loop through all the drops
									for (json Drop : Catalog)
									{
										// Make sure we are using the drop we opened
										if (!Drop["ProductID"].dump().find(std::to_string(5085)))
										{
											// Set the series id of the item
											seriesId = Drop["SeriesID"].get<int>();
											for (json Product : Drop["Drops"])
											{
												// Add the item to our list of possible items 
												CrateItems.push_back(stoi(Product["ProductID"].dump()));
											}
										}
									}

									int size = CrateItems.size();

									if (Events.cupopened_prospect)
									{
										Events.amountofspawnedtourneycreds = Events.amountofspawnedtourneycreds - 4000;

										for (auto product : CrateItems)
										{
											SProductData sproduct = Instances.GetProductData(product);

											int quality = sproduct.GetQuality();

											switch (quality) {
											case 1:
												for (int i = 0; i < 20; i++)
													CrateItems.push_back(product);
											case 2:
												for (int i = 0; i < 15; i++)
													CrateItems.push_back(product);
											case 3:
												for (int i = 0; i < 10; i++)
													CrateItems.push_back(product);
											case 4:
												for (int i = 0; i < 5; i++)
													CrateItems.push_back(product);
											case 5:
												for (int i = 0; i < 2; i++)
													CrateItems.push_back(product);
											}
										}
									}
									if (Events.cupopened_challengers)
									{
										Events.amountofspawnedtourneycreds = Events.amountofspawnedtourneycreds - 1200;

										for (auto product : CrateItems)
										{
											SProductData sproduct = Instances.GetProductData(product);

											int quality = sproduct.GetQuality();

											switch (quality) {
											case 1:
												for (int i = 0; i < 15; i++)
													CrateItems.push_back(product);
											case 2:
												for (int i = 0; i < 10; i++)
													CrateItems.push_back(product);
											case 3:
												for (int i = 0; i < 5; i++)
													CrateItems.push_back(product);
											case 4:
												for (int i = 0; i < 2; i++)
													CrateItems.push_back(product);
											case 5:
												for (int i = 0; i < 2; i++)
													CrateItems.push_back(product);
											}
										}
									}
									if (Events.cupopened_allstars)
									{
										Events.amountofspawnedtourneycreds = Events.amountofspawnedtourneycreds - 12000;

										for (auto product : CrateItems)
										{
											SProductData sproduct = Instances.GetProductData(product);

											int quality = sproduct.GetQuality();

											switch (quality) {
											case 1:
												for (int i = 0; i < 10; i++)
													CrateItems.push_back(product);
											case 2:
												for (int i = 0; i < 5; i++)
													CrateItems.push_back(product);
											case 3:
												for (int i = 0; i < 2; i++)
													CrateItems.push_back(product);
											case 4:
												for (int i = 0; i < 2; i++)
													CrateItems.push_back(product);
											case 5:
												for (int i = 0; i < 2; i++)
													CrateItems.push_back(product);
											}
										}
									}
									if (Events.cupopened_champions)
									{
										Events.amountofspawnedtourneycreds = Events.amountofspawnedtourneycreds - 20000;

										for (auto product : CrateItems)
										{
											SProductData sproduct = Instances.GetProductData(product);

											int quality = sproduct.GetQuality();

											switch (quality) {
											case 1:
												for (int i = 0; i < 10; i++)
													CrateItems.push_back(product);
											case 2:
												for (int i = 0; i < 5; i++)
													CrateItems.push_back(product);
											case 3:
												for (int i = 0; i < 2; i++)
													CrateItems.push_back(product);
											case 4:
												for (int i = 0; i < 0; i++)
													CrateItems.push_back(product);
											case 5:
												for (int i = 0; i < 0; i++)
													CrateItems.push_back(product);
											}
										}
									}

									if (Events.crateitem == 0)
										Events.crateitem = CrateItems[rand() % size];
									quality = 0;
								}

								catch (std::exception& e) {
									Console.Error(e.what());
								}

								catch (std::length_error& e) {
									Console.Error(e.what());
								}

								catch (json::parse_error& e) {
									Console.Error(e.what());
								}

								catch (json::other_error& e) {
									Console.Error(e.what());
								}

								catch (json::type_error& e) {
									Console.Error(e.what());
								}

								catch (json::exception& e) {
									Console.Error(e.what());
								}

								bool isPaintable = Instances.GetProductData(Events.crateitem).Paintable;

								if (isPaintable) {
									int paintSize = Events.paintValues.size();
									Events.crateitem_paint = Events.paintValues[rand() % paintSize];
								}

								int certSize = Events.certValues.size();
								Events.crateitem_cert = Events.certValues[rand() % certSize];

								if (Events.crateitem == 0) {
									Events.crateitem = 0;
									Events.crateitem_paint = 0;
									Events.crateitem_cert = 0;
									quality = -1;
								}

								if (Events.crateitem == 35 || Events.crateitem == 36 || Events.crateitem == 45 || Events.crateitem == 52 || Events.crateitem == 44 || Events.crateitem == 62 || Events.crateitem == 63 || Events.crateitem == 53 || Events.crateitem == 23 || Events.crateitem == 22 || Events.crateitem == 30 || Events.crateitem == 25 || Events.crateitem == 31 || Events.crateitem == 28)
								{
									quality = 4;
								}

								json finalbodyjson;

								json finalproductjson;
								finalproductjson["ProductID"] = Events.crateitem;
								finalproductjson["AddedTimestamp"] = Instances.GetTimestampLong();
								finalproductjson["InstanceID"] = Instances.GeneratePIIDstr(Events.crateitem);
								finalproductjson["Attributes"] = std::vector<json>{};

								if (Events.crateitem_paint != 0)
								{
									json attributejson;
									attributejson["Key"] = "Painted";
									attributejson["Value"] = std::to_string(Events.crateitem_paint);

									finalproductjson["Attributes"].push_back(attributejson);
								}

								if (Events.crateitem_cert != 0)
								{
									json attributejson;
									attributejson["Key"] = "Certified";
									attributejson["Value"] = std::to_string(Events.crateitem_cert);

									finalproductjson["Attributes"].push_back(attributejson);
								}

								if (quality != 0)
								{
									json attributejson;
									attributejson["Key"] = "Quality";
									attributejson["Value"] = Instances.GetQualityName(quality);

									finalproductjson["Attributes"].push_back(attributejson);
								}

								finalbodyjson["Result"]["ProductData"].push_back(finalproductjson);

								responseRequestMessage->Message->SetBodyText(Instances.to_fstring(finalbodyjson.dump()));
							}
						}					
					}

					if (psyservice == "Party/UserJoined v1") {
						if (Events.online_x) {
							bool mm = Events.online_x->IsInMainMenu();
							if (mm) {
								garageGFX = Instances.GetInstanceOf<UGFxData_Garage_TA>();
								if (garageGFX) {
									UCarPreviewSet_TA* previewSet = garageGFX->CarPreviewSet;
									if (previewSet) {
										previewactor = previewSet->GetPlayerCarPreviewActor(Instances.IULocalPlayer());
										if (previewactor) {
											UPremiumGaragePreviewSet_TA* premGarage = Instances.GetInstanceOf<UPremiumGaragePreviewSet_TA>();
											if (premGarage) {
												premGarage->CarPreviewActors.Clear();
												ACamera_X* camera = Instances.GetInstanceOf<ACamera_X>();

												if (camera) {
													FVector oldlocation = camera->Location;

													//previewactor->SetTurnTableActor(premGarage->GetTurntable(), previewactor->Rotation);
													FVector location = previewactor->Location;
													//location.Z = location.Z + 50;

													//previewactor->SetLocation(location);

													int index = 0;
													for (auto previewActor : previewSet->CarPreviewActors) {
														index++;

														if (index == 1 && previewActor == previewactor) {
															index = 0;
															continue;
														}

														if (previewActor != previewactor) {
															location.X = location.X - 333.33;
															previewActor->SetLocation(location);

														}
													}

													camera->Move(oldlocation);
												}
											}
										}
									}
								}
							}
						}					
					}

					//else if (psyservice.find("DSR/ClientMessage v1") != std::string::npos)
					//{
					//	json BodyJson = json::parse(responseRequestMessage->Message->GetBodyText().ToString());

					//	std::string RawMessagePayload = BodyJson["MessagePayload"].get<std::string>();

					//	Instances.ReplaceString(RawMessagePayload, "\\\"", "\"");

					//	//Console.Write("RawMessagePayload: " + RawMessagePayload);

					//	if (RawMessagePayload.find("PingAddress") != std::string::npos) {
					//		json MessagePayload;

					//		try {
					//			MessagePayload = json::parse(RawMessagePayload);
					//		}

					//		catch (json::exception& e) { Console.Error(e.what()); }

					//		if (MessagePayload.is_null() == false)
					//		{
					//			std::string oldServerAddress = MessagePayload["ServerAddress"].get<std::string>();
					//			size_t pos = oldServerAddress.find(":");
					//			std::string oldServerIP = oldServerAddress.substr(0, pos);
					//			std::string oldServerPort = oldServerAddress.substr(pos + 1);
					//			int oldserverport = stoi(oldServerPort);

					//			std::string key = MessagePayload["Keys"]["Key"];
					//			std::string iv = MessagePayload["Keys"]["IV"];

					//			MessagePayload["ServerAddress"] = "127.0.0.1:9024";
					//			MessagePayload.erase("PingAddress");

					//			std::string finalpayload = MessagePayload.dump();

					//			Instances.ReplaceString(finalpayload, "\"", "\"");

					//			BodyJson["MessagePayload"] = finalpayload;

					//			Console.Write("BodyJson: " + BodyJson.dump());

					//			FString finalte = Instances.to_fstring(BodyJson.dump());

					//			std::cout << "Game server: " << oldServerIP << ":" << oldserverport << std::endl;

					//			std::thread udpsocket([this, oldserverport, oldServerIP, iv, key] {
					//				boost::asio::io_context io_context;
					//				// Set the desired upstream and downstream port and address
					//				unsigned short downstreamPort = 9024;

					//				UDPServer server(io_context, downstreamPort, oldserverport, oldServerIP, iv, key);

					//				//udpsocket.detach();

					//				io_context.run();
					//			});

					//			udpsocket.detach();

					//			responseRequestMessage->Message->SetBodyText(finalte);
					//		}
					//	}
					//}	

					//else if (psyservice == "Ads/GetAds v1")  {
					//	std::string body = "{\"Result\":{\"Ads\":[{\"ZoneID\":202,\"Url\":\"" + Instances.GetVoltageCDNURL(Events.AD256) + "\",\"UTCEndTime\":\"\"},{\"ZoneID\":201,\"Url\":\"" + Instances.GetVoltageCDNURL(Events.AD256) + "\",\"UTCEndTime\":\"\"},{\"ZoneID\":403,\"Url\":\"" + Instances.GetVoltageCDNURL(Events.AD512) + "\",\"UTCEndTime\":\"\"},{\"ZoneID\":404,\"Url\":\"" + Instances.GetVoltageCDNURL(Events.AD512) + "\",\"UTCEndTime\":\"\"}]}}";
					//	responseRequestMessage->Message->SetBodyText(Instances.to_fstring(body));
					//}

					else if (psyservice == "Shops/GetPlayerWallet v1") {
						json bodyjson;
						std::string psyservice;
						try {
							bodyjson = json::parse(responseRequestMessage->Message->GetBodyText().ToString());
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

						USaveData_TA* saveData = Events.saveData;

						if (saveData)
						{
							UOnlinePlayer_TA* onlinePlayer = saveData->GetOnlinePlayer();
							if (onlinePlayer)
							{
								UWallet_TA* wallet = onlinePlayer->Wallet;
								if (wallet)
								{
									TArray<FCurrency> CorrectCurrencies;

									for (auto Currency : bodyjson["Result"]["Currencies"])
									{
										if (Currency["ID"].get<int>() == 26)
										{
											Currency["Amount"] = Currency["Amount"] + Events.amountofspawnedtourneycreds;
										}

										FCurrency Credits = wallet->GetCurrency(Currency["ID"].get<int>());

										Credits.Amount = Currency["Amount"].get<int>();

										CorrectCurrencies.Add(Credits);
									}

									wallet->UpdateWalletCurrencies(CorrectCurrencies);

									wallet->EventWalletUpdated(wallet);
								}
							}
						}
					}

					else if (psyservice == "Products/UnlockContainer v2") {
						if (responseRequestMessage->Message->GetBodyText().ToString().find("InventoryOutOfSync") != std::string::npos || responseRequestMessage->Message->GetBodyText().ToString().find("AccessDenied") != std::string::npos) {
							srand(std::chrono::system_clock::now().time_since_epoch().count());

							int quality = -1;
							int seriesId = 0;
							Events.crateitem = 0;
							Events.crateitem_cert = 0;
							Events.crateitem_paint = 0;

							if (Events.openedblackmarketdrop) {
								int size = Events.bmproducts.size();
								Events.crateitem = Events.bmproducts[rand() % size];
								Events.openedblackmarketdrop = false;
							}

							if (Events.openedexoticdrop) {
								int size = Events.exoproducts.size();
								Events.crateitem = Events.exoproducts[rand() % size];
								Events.openedexoticdrop = false;
							}

							if (Events.openedimportdrop) {
							    //std::vector<int> blackdropitems = { 23, 4284, 4770, 402, 5188, 1661, 1580, 376, 822, 731, 1581, 1905, 8493, 1907, 2023, 2702, 2817, 3703, 36, 45, 53, 63, 1092, 1552, 1553, 1565 };

								int size = Events.impproducts.size();
								Events.crateitem = Events.impproducts[rand() % size];
								if (Events.crateitem == 35 || Events.crateitem == 36 || Events.crateitem == 45 || Events.crateitem == 52 || Events.crateitem == 44 || Events.crateitem == 62 || Events.crateitem == 63 || Events.crateitem == 53 || Events.crateitem == 23 || Events.crateitem == 22 || Events.crateitem == 30 || Events.crateitem == 25 || Events.crateitem == 31 || Events.crateitem == 28)
								{
									quality = 4;
								}			
								if (Events.crateitem == 376) {
									quality = 2;
								}
								//Events.crateitem_paint = 3;
								Events.openedimportdrop = false;
							}

							if (Events.openedbonusgiftdrop) {
								std::vector<int> beachItems{ 4159,2423,4369,4249,3825,3878,4297,4462,4358,4268,4282,4173,4384,3763,4244,4118,3800,1456,1527,1059,1898,2359,4717,1584,1522,1092,731,1667,1580,1684,2702,2736,2817,4335,4371 };
								int size = beachItems.size();
								Events.crateitem = beachItems[rand() % size];
								Events.openedbonusgiftdrop = false;
							}

							if (Events.whichcrateiopened == 8991) {
								std::vector<int> beachItems{ 1775,1769,1770,1773,1774,1056,1767,1694,1691,1736,1784,1826,1667,1661,1579,1679,1684,1888,2339,2461,2544,2672,1981,2533,2555,2819,2853,2899,2916,2935,2971,2817,2915,2966,2967,1980,2012,2024,2336,2498,1975,2047,1974,1856,2054,2254,2392,2059,1604,2027,3528,1908,2329 };
								int size = beachItems.size();
								Events.crateitem = beachItems[rand() % size];
							}
							
							if (Events.whichcrateiopened == 8728) {
								std::vector<int> moonItems{ 2345,2346,2679,2551,1123,2407,3072,3220,3001,3031,3114,2972,3079,2702,3071,2966,3239,2540,2547,2548,2588,2693,1976,2695,2732,2070,2645,2654,2614,2729,2501,2694,2736,2702,1681,1917,1953,1955,1978,1898,1899,1900,1945,1638,1919,1932,1655,1929,1904,1905,1907,1908 };
								int size = moonItems.size();
								Events.crateitem = moonItems[rand() % size];
							}

							if (Events.whichcrateiopened == 5301) {
								int size = Events.raproducts.size();
								Events.crateitem = Events.raproducts[rand() % size];
							}

							if (Events.whichcrateiopened == 5302) {
								int size = Events.uncproducts.size();
								Events.crateitem = Events.uncproducts[rand() % size];
							}

							if (Events.whichcrateiopened == 5303) {
								int size = Events.vrproducts.size();
								Events.crateitem = Events.vrproducts[rand() % size];
							}

							if (Events.whichcrateiopened == 8458) {
								std::vector<int> giftItems{ 2411,2565,2917,2948,3144,1951,2409,3342,3459,3313,3331,3451,3337,3370,3071,3239,3453,3460,4159,2423,4369,4249,3825,4371,4297,4462,4358,4268,4282,4173,4384,3763,4244,4118,3800,1059,2693,1955,2551,1980,1423,2819,1975,1951,1856,2853,2837,1661,1580,2614,2854,2966,3239,3453 };
								int size = giftItems.size();
								Events.crateitem = giftItems[rand() % size];
							}

							if (Events.whichcrateiopened == 9107) {
								std::vector<int> meowItems{ 1435, 1436, 1437, 1438, 820, 517, 1295, 1158, 1018, 1423, 1047, 1096, 1131, 1130, 1102, 1456, 818, 731, 1300, 1159, 1092, 1449, 1093, 1079, 1059, 822, 819, 1416, 1542, 1551, 1502, 1532, 1527, 1581, 1580, 1584, 1568, 1565, 1564, 1561, 1544, 1545, 1546 };
								int size = meowItems.size();
								Events.crateitem = meowItems[rand() % size];
							}
							
							//golden trophy items
							if (Events.whichcrateiopened == 9329) {
								std::vector<int> potentialItems{ 1963, 2021, 2025, 2363, 1950, 2275, 2359, 2383, 1883, 1943, 2394, 825, 1931, 1907, 2027, 2044, 2349, 4159, 2423, 4369, 4249, 3825, 3878, 4297, 4462, 4335, 4268, 4282, 4173, 4384, 3763, 4244, 4118, 3800, 2340, 2460, 2535, 2581, 2629, 1060, 2512, 2767, 2850, 1894, 2778, 2837, 2758, 2827, 2694, 2702, 2817, 2854 };
								int size = potentialItems.size();
								Events.crateitem = potentialItems[rand() % size];
							}

							if (Events.crateitem == 0) {
								try {
									if (Events.CatalogJSON.length() < 3) {
										if (Events.CatalogJSON.length() < 3)
										{
											URPC_MicroTransactions_GetContainerDropTable_TA* getcatalog = Instances.CreateInstance<URPC_MicroTransactions_GetContainerDropTable_TA>();
											if (getcatalog)
												Instances.sendAPIRequest(getcatalog);
										}
										return;
									}

									std::vector<int> CrateItems;

									json Catalog = json::parse(Events.CatalogJSON)["Result"]["ContainerDrops"];

									// Loop through all the drops
									for (json Drop : Catalog)
									{
										// Make sure we are using the drop we opened
										if (!Drop["ProductID"].dump().find(std::to_string(Events.whichcrateiopened)))
										{
											// Set the series id of the item
											seriesId = Drop["SeriesID"].get<int>();
											for (json Product : Drop["Drops"])
											{
												// Add the item to our list of possible items 
												CrateItems.push_back(stoi(Product["ProductID"].dump()));
											}
										}
									}

									int size = CrateItems.size();

									if (Events.crateitem == 0)
										Events.crateitem = CrateItems[rand() % size];
									quality = 0;
								}

								catch (std::exception& e) {
									Console.Error(e.what());
								}

								catch (std::length_error& e) {
									Console.Error(e.what());
								}

								catch (json::parse_error& e) {
									Console.Error(e.what());
								}

								catch (json::other_error& e) {
									Console.Error(e.what());
								}

								catch (json::type_error& e) {
									Console.Error(e.what());
								}

								catch (json::exception& e) {
									Console.Error(e.what());
								}
							}

							if (Events.crateitem == 5364 || Events.crateitem == 5365 || Events.crateitem == 5366 || Events.crateitem == 5367 || Events.crateitem == 5368 || Events.crateitem == 5369) {
								std::vector<int> items = { 5972, 6160, 5914, 6008, 5584, 5844, 5335, 5304, 5318, 5966, 6007, 5985, 5885, 5448, 5354, 5881, 5361, 1126, 5215, 5343, 6019, 5963, 5659, 1963, 2021, 2025, 2363, 1950, 2275, 2359, 2383, 1883, 1943, 2394, 825, 1931, 1907, 2027, 2044, 2349, 2340, 2460, 2535, 2581, 2629, 1060, 2512, 2767, 2850, 1894, 2778, 2837, 2758, 2827, 2694, 2702, 2817, 2854 };
								Events.crateitem = items[rand() % items.size()];
							}
							UProduct_TA* product = Events.ProductDatabase->Products_New[Events.crateitem];

							if (!product)
								return;

							bool isPaintable = product->IsPaintable();

							if (isPaintable) {
								int paintSize = Events.paintValues.size();
								Events.crateitem_paint = Events.paintValues[rand() % paintSize];
							}
									
							int certSize = Events.certValues.size();
							Events.crateitem_cert = Events.certValues[rand() % certSize];
							
							if (Events.crateitem == 0) {
								Events.crateitem = 0;
								Events.crateitem_paint = 0;
								Events.crateitem_cert = 0;
								quality = -1;
							}

							//Events.crateitem_paint = 14;
							//Events.crateitem = 23;

							if (Events.crateitem == 35 || Events.crateitem == 36 || Events.crateitem == 45 || Events.crateitem == 52 || Events.crateitem == 44 || Events.crateitem == 62 || Events.crateitem == 63 || Events.crateitem == 53 || Events.crateitem == 23 || Events.crateitem == 22 || Events.crateitem == 30 || Events.crateitem == 25 || Events.crateitem == 31 || Events.crateitem == 28)
							{
								quality = 4;
							}

							json finalbodyjson;

							json finalproductjson;
							finalproductjson["ProductID"] = Events.crateitem;
							finalproductjson["InstanceID"] = Instances.GeneratePIIDstr(Events.crateitem);
							finalproductjson["Attributes"] = std::vector<json>{};

							if (Events.crateitem_paint != 0)
							{
								json attributejson;
								attributejson["Key"] = "Painted";
								attributejson["Value"] = std::to_string(Events.crateitem_paint);

								finalproductjson["Attributes"].push_back(attributejson);
							}

							if (Events.crateitem_cert != 0)
							{
								json attributejson;
								attributejson["Key"] = "Certified";
								attributejson["Value"] = std::to_string(Events.crateitem_cert);

								finalproductjson["Attributes"].push_back(attributejson);
							}

							//quality = 7;

							if (quality != 0)
							{
								json attributejson;
								attributejson["Key"] = "Quality";
								attributejson["Value"] = Instances.GetQualityName(quality);

								finalproductjson["Attributes"].push_back(attributejson);
							}

							finalbodyjson["Result"]["Drops"].push_back(finalproductjson);

							responseRequestMessage->Message->SetBodyText(Instances.to_fstring(finalbodyjson.dump()));
						}
					}

					std::string finalbodytext = responseRequestMessage->Message->GetBodyText().ToString();

					if (psytime != "0" && psyservice.find("SERVICEDSR")) {
						const std::string key = "3b932153785842ac927744b292e40e52";
						std::string data = "";
						data = psytime + "-" + finalbodytext;

						std::vector<uint8_t> NewPsySigVec(SHA256_HASH_SIZE);

						hmac_sha256(key.data(), key.size(), data.data(), data.size(), NewPsySigVec.data(), NewPsySigVec.size());

						std::stringstream ss_result;
						for (uint8_t x : NewPsySigVec) {
							ss_result << std::hex << std::setfill('0') << std::setw(2) << (int)x;
						}

						std::string NewPsySig(Instances.convert_to_base64((char*)ss_result.str().c_str()));

						responseRequestMessage->Message->Headers->Set(L"PsySig", Instances.to_fstring(NewPsySig));
					}

					Events.psynettrafficbodies.push_back(finalbodytext);
					Events.psynettrafficlogs.push_back("Response: " + Instances.quote(psyservice));

					std::string headers;
					for (int i = 0; i < requestResponseMap.Num(); i++) 
						headers = headers + requestResponseMap.At(i).Key.ToString() + ": " + requestResponseMap.At(i).Value.ToString() + "\n";

					Events.psynettrafficheaders.push_back(headers);

					if (psyservice.find("SERVICE") != std::string::npos) {
						Instances.ReplaceString(psyservice, "SERVICE", "");
						Console.WriteLog("Service Message: " + Instances.quote(psyservice) + ": " + finalbodytext);
					}
					else {
						Console.WriteLog("Request Response: " + Instances.quote(psyservice) + ": " + finalbodytext);
					}

					Events.totalrequests = Events.psynettrafficlogs.size();
				}
			}
	});
	HookEventPre("Function Engine.PlayerController.PlayerTick", &Hooks::PlayerControllerTick);
	HookEventPre("Function TAGame.GameViewportClient_TA.HandleKeyPress", &Hooks::GameViewPortKeyPress);
	HookEventPre("Function TAGame.GFxData_MainMenu_TA.MainMenuAdded", &Hooks::GFxDataMainMenuAdded);
	HookEventPost("Function TAGame.GFxData_PlayerVanity_TA.GetPlayerBannerIndex", &Hooks::GFxSetPlayerBanner);
	
	UServerConfig_X* serverConfig = Instances.GetInstanceOf<UServerConfig_X>();

	if (serverConfig)
	{
		serverConfig->bUploadLogFiles = false;
		serverConfig->bUploadReplays = false;

		serverConfig->Apply();
	}

	//HookEventPost("Function TAGame.Car_TA.SetVehicleInput", [&](const PostEvent& event) {
	//	Events.predictOn = true;
	//	if (Events.predictOn) {
	//		AGameEvent_Soccar_TA* gameEvent = Events.localGameEvent;

	//		if (!gameEvent)
	//			return;

	//		for (ABall_TA* ball : gameEvent->GameBalls) {
	//			if (!ball)
	//				return;

	//			int startIdx = currentStep * (predictStepSize);
	//			Ball chipBall;
	//			bool lastDirection[3];
	//			if (currentStep != 0)
	//			{
	//				startIdx -= 1;
	//				PredictedPoint pp = predictedBallPoints[startIdx];
	//				chipBall.x.X = pp.location.X;
	//				chipBall.x.Y = pp.location.Y;
	//				chipBall.x.Z = pp.location.Z;

	//				chipBall.v.X = pp.velocity.X;
	//				chipBall.v.Y = pp.velocity.Y;
	//				chipBall.v.Z = pp.velocity.Z;

	//				chipBall.w.X = pp.angVel.X;
	//				chipBall.w.Y = pp.angVel.Y;
	//				chipBall.w.Z = pp.angVel.Z;
	//				lastDirection[0] = pp.velocity.X >= 0;
	//				lastDirection[1] = pp.velocity.Y >= 0;
	//				lastDirection[2] = pp.velocity.Z >= 0;
	//			}
	//			else
	//			{
	//				//Get ball info from game
	//				FVector location = ball->Location;
	//				FVector velocity = ball->Velocity;
	//				FVector angVel = ball->AngularVelocity;
	//				predictedBallPoints[0] = { location, false };
	//				chipBall.x.X = location.X;
	//				chipBall.x.Y = location.Y;
	//				chipBall.x.Z = location.Z;

	//				chipBall.v.X = velocity.X;
	//				chipBall.v.Y = velocity.Y;
	//				chipBall.v.Z = velocity.Z;

	//				chipBall.w.X = angVel.X;
	//				chipBall.w.Y = angVel.Y;
	//				chipBall.w.Z = angVel.Z;
	//				lastDirection[0] = velocity.X >= 0;
	//				lastDirection[1] = velocity.Y >= 0;
	//				lastDirection[2] = velocity.Z >= 0;
	//			}
	//			//Store velocities to later determine bounces/apices

	//			//Step X physics ticks ahead (determined by cvar cl_soccar_predictball_steps
	//			int i = 0;
	//			int max = (currentStep * (predictStepSize) + (predictStepSize));
	//			for (i = startIdx + 1; i < max; i++)
	//			{
	//				bool isApex = false;
	//				//Chips example is 1/61, but setvehicleinputs is tied to physics tickrate @ 120
	//				chipBall.step((1.f / 61.f) * .5f);
	//				chipBall.step((1.f / 61.f) * .5f);
	//				bool currentDirection[3] = { chipBall.v.X >= 0, chipBall.v.Y >= 0, chipBall.v.Z >= 0 };
	//				FVector apexLocation = { 0, 0, 0 };
	//				if (currentDirection[0] != lastDirection[0])
	//				{
	//					isApex = true;
	//					apexLocation.X = 93 * ((lastDirection[0]) ? 1 : -1);
	//					lastDirection[0] = currentDirection[0];
	//				}
	//				if (currentDirection[1] != lastDirection[1])
	//				{
	//					isApex = true;
	//					apexLocation.Y = 93 * ((lastDirection[1]) ? 1 : -1);
	//					lastDirection[1] = currentDirection[1];
	//				}
	//				if (currentDirection[2] != lastDirection[2])
	//				{
	//					isApex = true;
	//					apexLocation.Z = 93 * ((lastDirection[2]) ? 1 : -1);
	//					lastDirection[2] = currentDirection[2];
	//				}
	//				predictedBallPoints[i] = { {chipBall.x.X, chipBall.x.Y, chipBall.x.Z}, isApex, apexLocation };
	//			}
	//			predictedBallPoints[i - 1].velocity = { chipBall.v.X, chipBall.v.Y, chipBall.v.Z };
	//			predictedBallPoints[i - 1].angVel = { chipBall.w.X, chipBall.w.Y, chipBall.w.Z };
	//			currentStep++;
	//			if (currentStep >= (predictSteps) / (predictStepSize))
	//			{
	//				currentStep = 0;
	//			}
	//		}
	//	}
	//});

	HookEventPost("Function TAGame.GFxData_MainMenu_TA.MainMenuAdded", [&](const PostEvent& event) {
		try {
			Events.blogConfig = Instances.GetInstanceOf<UBlogConfig_X>();
			if (Events.blogConfig) {
				Events.blogConfig->Entries.Clear();
				Events.blogConfig->MotD = Instances.to_fstring(Events.MOTD);
				Events.blogConfig->ModifyObjects(Events.blogConfig->StaticClass(), FScriptDelegate{}, FScriptDelegate{});
			}
		}

		catch (std::bad_alloc& b) {}
		catch (std::length_error& e) {}
		catch (std::exception& e) {}
		catch (SE_Exception& e) {}
		catch (std::bad_exception& e) {}

		if (!Events.eventrecorder)
			Events.eventrecorder = Instances.GetInstanceOf<UEventRecorderConfig_X>();
		if (Events.eventrecorder) {
			Events.eventrecorder->bEnabled = false;
			Events.eventrecorder->Apply();
		}
		if (Events.adblocker) {
			UChallengeConfig_TA* ChallengeConfig = Instances.GetInstanceOf<UChallengeConfig_TA>();

			if (ChallengeConfig)
			{
				ChallengeConfig->bHideChallengeUI = true;
				ChallengeConfig->Apply();
			}

			if (!Events.esportsConfig)
				Events.esportsConfig = Instances.GetInstanceOf<UESportConfig_TA>();
			if (Events.esportsConfig) {
				for (auto& event : Events.esportsConfig->Events)
				{
					event.bLiveNow = false;
					event.bStartingSoon = false;
					event.StartTime = L"";
					event.EndTime = L"";
					event.EpochStartTime = 0;
					event.EpochEndTime = 0;
					event.URL = L"";
				}

				TArray<FESportEventData> eventData;
				memcpy_s(&Events.esportsConfig->Events, sizeof(TArray<FESportEventData>), &eventData, sizeof(TArray<FESportEventData>));

				Events.esportsConfig->ModifyObjects(Events.esportsConfig->StaticClass(), FScriptDelegate{}, FScriptDelegate{});

				Events.esportsConfig->UpdateEvents();
			}
			if (!Events.rocketpass)
				Events.rocketpass = Instances.GetInstanceOf<UGFxData_RocketPass_TA>();
			if (Events.rocketpass) {
				if (!Events.rpass)
					Events.rpass = Events.rocketpass->RocketPass;
				if (Events.rpass) {
					if (!Events.rpcfg)
						Events.rpcfg = Events.rpass->RocketPassConfig;
					if (Events.rpcfg) {
						if (Events.rpcfg) {
							if (Events.rpass) {
								if (Events.rpass->bIsPassActive == true) {
									Events.rpass->bIsPassActive = false;
									Events.rpass->UpdateState();
								}
							}
							if (Events.rpcfg->bHideMainMenuButton == false) {
								Events.rpcfg->EndTime = Events.rpcfg->StartTime;
								Events.rpcfg->bHideMainMenuButton = true;
								Events.rpcfg->bIsActive = false;
								Events.rpcfg->Apply();
								Events.rpcfg->UpdateActiveState();
								Events.rocketpass->EndTime = Events.rocketpass->StartTime;
								Events.rocketpass->bHideMainMenuButton = true;
								Events.rocketpass->HandleRocketPassConfigChange();
							}
						}
					}
				}
			}
			if (!Events.shopcfg)
				Events.shopcfg = Instances.GetInstanceOf<UShopsConfig_TA>();
			if (Events.shopcfg) {
				if (Events.shopcfg) {
					if (Events.shopcfg->bHideMainMenuButton == false) {
						Events.shopcfg->bHideMainMenuButton = true;
						Events.shopcfg->bEnableShopMetrics = false;
						Events.shopcfg->Apply();
						if (!Events.gfxshops)
							Events.gfxshops = Instances.GetInstanceOf<UGFxData_Shops_TA>();
						if (Events.gfxshops) {
							Events.gfxshops->bHideMainMenuButton = true;
							Events.gfxshops->HandleConfigChanged();
							Events.gfxshops->RefreshAllShops();
						}
					}
				}
			}
			if (!Events.challengemgr)
				Events.challengemgr = Instances.GetInstanceOf<UChallengeManager_TA>();
			if (Events.challengemgr) {
				if (Events.challengemgr) {
					for (UChallenge_TA* challenge : Events.challengemgr->Challenges)
					{
						challenge->bIsHidden = true;
						challenge->bIsAchievement = false;
						challenge->bIsRepeatable = false;
						challenge->bNotifyNewInfo = false;
						challenge->bRewardsAvailable = false;
						Events.challengemgr->RemoveChallenge(challenge->Id);
					}
					Events.challengemgr->RemoveChallenges();
				}
			}
		}
		/*garageGFX = Instances.GetInstanceOf<UGFxData_Garage_TA>();
		if (garageGFX) {
			UCarPreviewSet_TA* previewSet = garageGFX->CarPreviewSet;
			if (previewSet) {
				previewactor = previewSet->GetPlayerCarPreviewActor(Instances.IULocalPlayer());
				if (previewactor) {
					const int original = previewactor->PreviewTeam;

					Events.cachedloadoutblue.Products.Clear();
					Events.cachedloadoutorange.Products.Clear();

					garageGFX->SetPreviewTeam(0);
					for (int product : previewactor->Loadout.Products) {
						Events.cachedloadoutblue.Products.Add(product);
					}
					garageGFX->SetPreviewTeam(1);
					for (int product : previewactor->Loadout.Products) {
						Events.cachedloadoutorange.Products.Add(product);
					}

					garageGFX->SetPreviewTeam(original);
				}
			}
		}*/
		if (premiumgaragemenu) {
			garageGFX = Instances.GetInstanceOf<UGFxData_Garage_TA>();
			if (garageGFX) {
				UCarPreviewSet_TA* previewSet = garageGFX->CarPreviewSet;
				if (previewSet) {
					previewactor = previewSet->GetPlayerCarPreviewActor(Instances.IULocalPlayer());
					if (previewactor) {
						UPremiumGaragePreviewSet_TA* premGarage = Instances.GetInstanceOf<UPremiumGaragePreviewSet_TA>();
						if (premGarage) {
							premGarage->CarPreviewActors.Clear();
							previewactor->SetTurnTableActor(premGarage->GetTurntable(), previewactor->Rotation);
							FVector location = previewactor->Location;
							location.Z = location.Z + 50;

							previewactor->SetLocation(location);

							int index = 0;
							for (auto previewActor : previewSet->CarPreviewActors) {
								index++;

								if (index == 1 && previewActor == previewactor) {
									index = 0;
									continue;
								}

								if (previewActor != previewactor) {
									location.X = location.X - 333.33;
									previewActor->SetLocation(location);
								}
							}
						}
					}
				}
			}
		}
		if (turntablemainmenu) {
			Events.garageGFX = Instances.GetInstanceOf<UGFxData_Garage_TA>();
			if (Events.garageGFX) {
				UCarPreviewSet_TA* previewSet = Events.garageGFX->CarPreviewSet;
				if (previewSet) {
					Events.previewactor = previewSet->GetPlayerCarPreviewActor(Instances.IULocalPlayer());
					if (Events.previewactor) {
						UPremiumGaragePreviewSet_TA* premGarage = Instances.GetInstanceOf<UPremiumGaragePreviewSet_TA>();
						if (premGarage) {
							premGarage->CarPreviewActors.Clear();

							ATurnTableActor_TA* turntable = premGarage->GetTurntable();

							FVector location = Events.previewactor->Location;
							//location.Z = location.Z + 5;
							//location.X = location.X - 70 * 9;
							turntable->SetLocation(location);

							Events.previewactor->SetTurnTableActor(turntable, Events.previewactor->Rotation);

							location.Z = location.Z + 6;

							Events.previewactor->SetLocation(location);
						}
					}
				}
			}
		}
	});

	Console.Write(GetNameFormatted() + std::to_string(PreHookedEvents.size()) + " Pre-Hook(s) Initialized!");
	Console.Write(GetNameFormatted() + std::to_string(PostHookedEvents.size()) + " Post-Hook(s) Initialized!");
	Console.Write(GetNameFormatted() + std::to_string(BlacklistedEvents.size()) + " Backlisted Event(s) Initialized!");

	Console.Write("[Inventory Module] Initialized!");
	Console.Write("[Persona Module] Initialized!");
	Console.Write("[Custom Title Module] Initialized!");
	Console.Write("[Psynet Traffic Module] Initialized!");

	try {
		Events.blogConfig = Instances.GetInstanceOf<UBlogConfig_X>();
		if (Events.blogConfig) {
			Events.blogConfig->Entries.Clear();
			Events.blogConfig->MotD = Instances.to_fstring(Events.MOTD);
			Events.blogConfig->ModifyObjects(Events.blogConfig->StaticClass(), FScriptDelegate{}, FScriptDelegate{});
		}
	}

	catch (std::bad_alloc& b) {}
	catch (std::length_error& e) {}
	catch (std::exception& e) {}
	catch (SE_Exception& e) {}
	catch (std::bad_exception& e) {}

	if (Events.adblocker) {
		UChallengeConfig_TA* ChallengeConfig = Instances.GetInstanceOf<UChallengeConfig_TA>();

		if (ChallengeConfig)
		{
			ChallengeConfig->bHideChallengeUI = true;
			ChallengeConfig->Apply();
			ChallengeConfig->ModifyObjects(ChallengeConfig->StaticClass(), FScriptDelegate{}, FScriptDelegate{});
		}

		if (!Events.esportsConfig)
			Events.esportsConfig = Instances.GetInstanceOf<UESportConfig_TA>();
		if (Events.esportsConfig) {
			for (auto& event : Events.esportsConfig->Events)
			{
				event.bLiveNow = false;
				event.bStartingSoon = false;
				event.StartTime = L"";
				event.EndTime = L"";
				event.EpochStartTime = 0;
				event.EpochEndTime = 0;
				event.URL = L"";
			}

			TArray<FESportEventData> eventData;
			memcpy_s(&Events.esportsConfig->Events, sizeof(TArray<FESportEventData>), &eventData, sizeof(TArray<FESportEventData>));

			Events.esportsConfig->ModifyObjects(Events.esportsConfig->StaticClass(), FScriptDelegate{}, FScriptDelegate{});

			Events.esportsConfig->UpdateEvents();
		}
		if (!Events.rocketpass)
			Events.rocketpass = Instances.GetInstanceOf<UGFxData_RocketPass_TA>();
		if (Events.rocketpass) {
			if (!Events.rpass)
				Events.rpass = Events.rocketpass->RocketPass;
			if (Events.rpass) {
				if (!Events.rpcfg)
					Events.rpcfg = Events.rpass->RocketPassConfig;
				if (Events.rpcfg) {
					if (Events.rpcfg) {
						if (Events.rpass) {
							if (Events.rpass->bIsPassActive == true) {
								Events.rpass->bIsPassActive = false;
								Events.rpass->UpdateState();
							}
						}
						if (Events.rpcfg->bHideMainMenuButton == false) {
							Events.rpcfg->EndTime = Events.rpcfg->StartTime;
							Events.rpcfg->bHideMainMenuButton = true;
							Events.rpcfg->bIsActive = false;
							Events.rpcfg->Apply();
							Events.rpcfg->UpdateActiveState();
							Events.rocketpass->EndTime = Events.rocketpass->StartTime;
							Events.rocketpass->bHideMainMenuButton = true;
							Events.rocketpass->HandleRocketPassConfigChange();
						}
					}
				}
			}
		}
		if (!Events.shopcfg)
			Events.shopcfg = Instances.GetInstanceOf<UShopsConfig_TA>();
		if (Events.shopcfg) {
			if (Events.shopcfg) {
				if (Events.shopcfg->bHideMainMenuButton == false) {
					Events.shopcfg->bHideMainMenuButton = true;
					Events.shopcfg->bEnableShopMetrics = false;
					Events.shopcfg->Apply();
					if (!Events.gfxshops)
						Events.gfxshops = Instances.GetInstanceOf<UGFxData_Shops_TA>();
					if (Events.gfxshops) {
						Events.gfxshops->bHideMainMenuButton = true;
						Events.gfxshops->HandleConfigChanged();
						Events.gfxshops->RefreshAllShops();
					}
				}
			}
		}
		if (!Events.challengemgr)
			Events.challengemgr = Instances.GetInstanceOf<UChallengeManager_TA>();
		if (Events.challengemgr) {
			if (Events.challengemgr) {
				for (UChallenge_TA* challenge : Events.challengemgr->Challenges)
				{
					challenge->bIsHidden = true;
					challenge->bIsAchievement = false;
					challenge->bIsRepeatable = false;
					challenge->bNotifyNewInfo = false;
					challenge->bRewardsAvailable = false;
					Events.challengemgr->RemoveChallenge(challenge->Id);
				}
				Events.challengemgr->RemoveChallenges();
			}
		}
	}
}

class EventsComponent Events {};