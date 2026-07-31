# AssetBundle decryptor for Desktop Mate

A small program for decrypting/encrypting the asset bundles of Desktop Mate. Could be used to extract resources or import custom models.

## Note: This program is only guaranteed to work with the specified version.

### Current version: **1.13.0**

## Usage

```
executable-file [-oevm] <input>

  -o, --output          Output file

  -e, --encrypt         Encrypt the input file into .cb asset bundle

  -v, --file-version    File version to set in the encrypted asset bundle. Need to be identical to the version specified in database.info.

  -m, --decrypt-mesh    Decrypt the mesh in the asset bundle. Should be enabled for all dlc characters.

  input                 File to process, for example character.cb
```

## How to build asset bundle for custom characters
1. Get a VRM model for the target character. If you have an FBX model, you could follow [the guide](https://vrm.dev/en/vrm/how_to_make_vrm/) to build one.
2. Import the [example project](ExampleProject/) to Unity.
![](images/imported_project.png)
3. Get the animation clips for your character. You will need animations for Standing(oneShot and loop), Sitting(oneShot and loop), Dragged, Stroked(standing and sitting), Picked(standing and sitting), JumpOut, JumpIn, HideLeft, HideRight and Alarm. If the official animations fit your character well, you could extract them from the decrypted asset bundle with [AssetRipper](https://github.com/AssetRipper/AssetRipper).
	- Extract the assets with AssetRipper
	![](images/export_assets.png)
	- The official animation clips for Miku
	![](images/miku_animation_clips.png)
4. Import the animation clips to Unity. Create an animation controller asset (or use the corresponding official one if you are using the official animation clips). Add all the animation clips to the Base Layer of the animation controller.
	- The official animation controller asset in the asset bundle
	![](images/controller_asset.png)
	- Imported to Unity
	![](images/miku_animation_controller.png)
5. Import your VRM model to Unity and drag it to the Scene Hierarchy. In the Animator component, select the animation controller in step 4 as controller. Attach [CharaData](ExampleProject/Assets/Scripts/CharaData.cs) to the prefab and set the arguments for animation playing. You could copy the official ones (from the CharaData MonoBehaviour extracted from the asset bundle, or by directly importing the asset bundle to Unity).
	- Select the imported animation controller in Inspector
	![](images/add_component.png)
	- Copy the CharaData component from the imported asset bundle (you'll need a simple Editor script to import it) to the target prefab. You might also manually add the script component and customize the arguments.
	![](images/CharaData_params.png)
6. Configure MagicaCloth2 for cloth and hair physics simulating.
	1. Add MagicaCloth object for each hair or cloth component that needs physics simulation to the prefab
	![](images/add_magicacloth.png)
	2. Configure the MagicaCloth object. Normally we'll use BoneCloth if the target component is tied to bones. Add the root bones and select a preset (or set the parameters yourself). If the target component isn't tied to bones, use MeshCloth instead.
	![](images/configure_magicacloth.png)
	3. Add MagicaCollider objects to the armature. Register the colliders that a certain component might collide to to the `Collider Collision` section of the corresponding MagicaCloth object.
	![](images/configure_magicacollider.png)
	- All the configured MagicaCloth objects
	![](images/configured_magicacloth.png)
7. Drag the prefab to assets view to save the prefab. Rename it as `iltan_prefab` or `miku_prefab` depending on which character you'd like to override. Select the saved prefab and assign it to an asset bundle (at the bottom of the Inspector window) named `iltan` or `miku`.
![](images/save_prefab.png)
8. Open `Window->AssetBundle Browser` and build the asset bundle. Copy the exported asset bundle to `DesktopMate_Data\StreamingAssets\AssetBundle` of your installation path. Make sure the file name is `iltan` or `miku`. Run the decryptor with `executable-file <path/to/AssetBundle/directory> <AssetBundleType> E` to encrypt the asset bundle (remember to backup the original one).
	- Build asset bundle
	![](images/build_assetbundle.png)
	- The exported asset bundle
	![](images/exported_assetbundle.png)
	- Encrypted assset bundle
	![](images/encrypted_assetbundle.png)
9. Launch the game and enjoy!
	- Final effect
	![](images/result.png)
