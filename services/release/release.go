// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package release

import (
	"context"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"code.gitea.io/gitea/models"
	"code.gitea.io/gitea/models/db"
	git_model "code.gitea.io/gitea/models/git"
	repo_model "code.gitea.io/gitea/models/repo"
	user_model "code.gitea.io/gitea/models/user"
	"code.gitea.io/gitea/modules/container"
	"code.gitea.io/gitea/modules/git"
	"code.gitea.io/gitea/modules/log"
	"code.gitea.io/gitea/modules/repository"
	"code.gitea.io/gitea/modules/storage"
	"code.gitea.io/gitea/modules/timeutil"
	"code.gitea.io/gitea/modules/util"
	notify_service "code.gitea.io/gitea/services/notify"

	kmsapi "chungus/saq/pqc/cryptoservice/proto/api/v1"
	kmspb "chungus/saq/pqc/cryptoservice/proto/api/v1/kms"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func createTag(ctx context.Context, gitRepo *git.Repository, rel *repo_model.Release, msg string) (bool, error) {
	err := rel.LoadAttributes(ctx)
	if err != nil {
		return false, err
	}

	err = rel.Repo.MustNotBeArchived()
	if err != nil {
		return false, err
	}

	var created bool
	// Only actual create when publish.
	if !rel.IsDraft {
		if !gitRepo.IsTagExist(rel.TagName) {
			if err := rel.LoadAttributes(ctx); err != nil {
				log.Error("LoadAttributes: %v", err)
				return false, err
			}

			protectedTags, err := git_model.GetProtectedTags(ctx, rel.Repo.ID)
			if err != nil {
				return false, fmt.Errorf("GetProtectedTags: %w", err)
			}

			// Trim '--' prefix to prevent command line argument vulnerability.
			rel.TagName = strings.TrimPrefix(rel.TagName, "--")
			isAllowed, err := git_model.IsUserAllowedToControlTag(ctx, protectedTags, rel.TagName, rel.PublisherID)
			if err != nil {
				return false, err
			}
			if !isAllowed {
				return false, models.ErrProtectedTagName{
					TagName: rel.TagName,
				}
			}

			commit, err := gitRepo.GetCommit(rel.Target)
			if err != nil {
				return false, fmt.Errorf("createTag::GetCommit[%v]: %w", rel.Target, err)
			}

			if len(msg) > 0 {
				if err = gitRepo.CreateAnnotatedTag(rel.TagName, msg, commit.ID.String()); err != nil {
					if strings.Contains(err.Error(), "is not a valid tag name") {
						return false, models.ErrInvalidTagName{
							TagName: rel.TagName,
						}
					}
					return false, err
				}
			} else if err = gitRepo.CreateTag(rel.TagName, commit.ID.String()); err != nil {
				if strings.Contains(err.Error(), "is not a valid tag name") {
					return false, models.ErrInvalidTagName{
						TagName: rel.TagName,
					}
				}
				return false, err
			}
			created = true
			rel.LowerTagName = strings.ToLower(rel.TagName)

			commits := repository.NewPushCommits()
			commits.HeadCommit = repository.CommitToPushCommit(commit)
			commits.CompareURL = rel.Repo.ComposeCompareURL(git.EmptySHA, commit.ID.String())

			refFullName := git.RefNameFromTag(rel.TagName)
			notify_service.PushCommits(
				ctx, rel.Publisher, rel.Repo,
				&repository.PushUpdateOptions{
					RefFullName: refFullName,
					OldCommitID: git.EmptySHA,
					NewCommitID: commit.ID.String(),
				}, commits)
			notify_service.CreateRef(ctx, rel.Publisher, rel.Repo, refFullName, commit.ID.String())
			rel.CreatedUnix = timeutil.TimeStampNow()
		}
		commit, err := gitRepo.GetTagCommit(rel.TagName)
		if err != nil {
			return false, fmt.Errorf("GetTagCommit: %w", err)
		}

		rel.Sha1 = commit.ID.String()
		rel.NumCommits, err = commit.CommitsCount()
		if err != nil {
			return false, fmt.Errorf("CommitsCount: %w", err)
		}

		if rel.PublisherID <= 0 {
			u, err := user_model.GetUserByEmail(ctx, commit.Author.Email)
			if err == nil {
				rel.PublisherID = u.ID
			}
		}
	} else {
		rel.CreatedUnix = timeutil.TimeStampNow()
	}
	return created, nil
}

type RemoteSigner struct {
	crypto.Signer
	client kmspb.CryptoKeyManagementServiceClient
	pk     crypto.PublicKey
	key    *kmsapi.CryptoKey
}

func (r *RemoteSigner) Public() crypto.PublicKey {
	return r.pk
}

func (r *RemoteSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	signResp, err := r.client.Sign(context.Background(), &kmspb.SignReq{
		Key:    r.key,
		Digest: digest,
	})
	if err != nil {
		return nil, err
	}
	return signResp.Signed, nil
}

func RemoteSignRelease(gitRepo *git.Repository, key_alias string, attachmentUUIDs []string) (sigHash string, err error) {
	hash, err := repo_model.GenAttachmentsHash(gitRepo.Ctx, attachmentUUIDs)
	if err != nil {
		return "hash_fail", err
	}

	conn, err := grpc.Dial("0.0.0.0:9876", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return "hash_fail", err
	}
	client := kmspb.NewCryptoKeyManagementServiceClient(conn)

	listKeysResp, err := client.ListKeys(context.Background(), &kmspb.ListKeysReq{})
	if err != nil {
		return "hash_fail", err
	}

	var crypto_keyref *kmsapi.CryptoKey

	for _, key := range listKeysResp.GetKeys() {
		if key.Name == key_alias {
			crypto_keyref = key
			break
		}
	}

	signResp, err := client.Sign(context.Background(), &kmspb.SignReq{
		Key:    crypto_keyref,
		Digest: []byte(hash),
	})
	if err != nil {
		return "hash_fail", err
	}

	signedHash := signResp.Signed
	signedHashHex := hex.EncodeToString(signedHash)

	log.Info("Signed Hash: %s", signedHashHex)
	return signedHashHex, nil

}

// CreateRelease creates a new release of repository.
func CreateRelease(gitRepo *git.Repository, rel *repo_model.Release, attachmentUUIDs []string, msg string) error {
	has, err := repo_model.IsReleaseExist(gitRepo.Ctx, rel.RepoID, rel.TagName)
	if err != nil {
		return err
	} else if has {
		return repo_model.ErrReleaseAlreadyExist{
			TagName: rel.TagName,
		}
	}

	if _, err = createTag(gitRepo.Ctx, gitRepo, rel, msg); err != nil {
		return err
	}

	rel.LowerTagName = strings.ToLower(rel.TagName)
	if err = db.Insert(gitRepo.Ctx, rel); err != nil {
		return err
	}

	if err = repo_model.AddReleaseAttachments(gitRepo.Ctx, rel.ID, attachmentUUIDs); err != nil {
		return err
	}

	if !rel.IsDraft {
		notify_service.NewRelease(gitRepo.Ctx, rel)
	}

	return nil
}

// CreateNewTag creates a new repository tag
func CreateNewTag(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, commit, tagName, msg string) error {
	has, err := repo_model.IsReleaseExist(ctx, repo.ID, tagName)
	if err != nil {
		return err
	} else if has {
		return models.ErrTagAlreadyExists{
			TagName: tagName,
		}
	}

	gitRepo, closer, err := git.RepositoryFromContextOrOpen(ctx, repo.RepoPath())
	if err != nil {
		return err
	}
	defer closer.Close()

	rel := &repo_model.Release{
		RepoID:       repo.ID,
		Repo:         repo,
		PublisherID:  doer.ID,
		Publisher:    doer,
		TagName:      tagName,
		Target:       commit,
		IsDraft:      false,
		IsPrerelease: false,
		IsTag:        true,
	}

	if _, err = createTag(ctx, gitRepo, rel, msg); err != nil {
		return err
	}

	return db.Insert(ctx, rel)
}

// UpdateRelease updates information, attachments of a release and will create tag if it's not a draft and tag not exist.
// addAttachmentUUIDs accept a slice of new created attachments' uuids which will be reassigned release_id as the created release
// delAttachmentUUIDs accept a slice of attachments' uuids which will be deleted from the release
// editAttachments accept a map of attachment uuid to new attachment name which will be updated with attachments.
func UpdateRelease(ctx context.Context, doer *user_model.User, gitRepo *git.Repository, rel *repo_model.Release,
	addAttachmentUUIDs, delAttachmentUUIDs []string, editAttachments map[string]string,
) error {
	if rel.ID == 0 {
		return errors.New("UpdateRelease only accepts an exist release")
	}
	isCreated, err := createTag(gitRepo.Ctx, gitRepo, rel, "")
	if err != nil {
		return err
	}
	rel.LowerTagName = strings.ToLower(rel.TagName)

	ctx, committer, err := db.TxContext(ctx)
	if err != nil {
		return err
	}
	defer committer.Close()

	if err = repo_model.UpdateRelease(ctx, rel); err != nil {
		return err
	}

	if err = repo_model.AddReleaseAttachments(ctx, rel.ID, addAttachmentUUIDs); err != nil {
		return fmt.Errorf("AddReleaseAttachments: %w", err)
	}

	deletedUUIDs := make(container.Set[string])
	if len(delAttachmentUUIDs) > 0 {
		// Check attachments
		attachments, err := repo_model.GetAttachmentsByUUIDs(ctx, delAttachmentUUIDs)
		if err != nil {
			return fmt.Errorf("GetAttachmentsByUUIDs [uuids: %v]: %w", delAttachmentUUIDs, err)
		}
		for _, attach := range attachments {
			if attach.ReleaseID != rel.ID {
				return util.SilentWrap{
					Message: "delete attachment of release permission denied",
					Err:     util.ErrPermissionDenied,
				}
			}
			deletedUUIDs.Add(attach.UUID)
		}

		if _, err := repo_model.DeleteAttachments(ctx, attachments, true); err != nil {
			return fmt.Errorf("DeleteAttachments [uuids: %v]: %w", delAttachmentUUIDs, err)
		}
	}

	if len(editAttachments) > 0 {
		updateAttachmentsList := make([]string, 0, len(editAttachments))
		for k := range editAttachments {
			updateAttachmentsList = append(updateAttachmentsList, k)
		}
		// Check attachments
		attachments, err := repo_model.GetAttachmentsByUUIDs(ctx, updateAttachmentsList)
		if err != nil {
			return fmt.Errorf("GetAttachmentsByUUIDs [uuids: %v]: %w", updateAttachmentsList, err)
		}
		for _, attach := range attachments {
			if attach.ReleaseID != rel.ID {
				return util.SilentWrap{
					Message: "update attachment of release permission denied",
					Err:     util.ErrPermissionDenied,
				}
			}
		}

		for uuid, newName := range editAttachments {
			if !deletedUUIDs.Contains(uuid) {
				if err = repo_model.UpdateAttachmentByUUID(ctx, &repo_model.Attachment{
					UUID: uuid,
					Name: newName,
				}, "name"); err != nil {
					return err
				}
			}
		}
	}

	if err := committer.Commit(); err != nil {
		return err
	}

	for _, uuid := range delAttachmentUUIDs {
		if err := storage.Attachments.Delete(repo_model.AttachmentRelativePath(uuid)); err != nil {
			// Even delete files failed, but the attachments has been removed from database, so we
			// should not return error but only record the error on logs.
			// users have to delete this attachments manually or we should have a
			// synchronize between database attachment table and attachment storage
			log.Error("delete attachment[uuid: %s] failed: %v", uuid, err)
		}
	}

	if !isCreated {
		notify_service.UpdateRelease(gitRepo.Ctx, doer, rel)
		return nil
	}

	if !rel.IsDraft {
		notify_service.NewRelease(gitRepo.Ctx, rel)
	}

	return nil
}

// DeleteReleaseByID deletes a release and corresponding Git tag by given ID.
func DeleteReleaseByID(ctx context.Context, repo *repo_model.Repository, rel *repo_model.Release, doer *user_model.User, delTag bool) error {
	if delTag {
		protectedTags, err := git_model.GetProtectedTags(ctx, rel.RepoID)
		if err != nil {
			return fmt.Errorf("GetProtectedTags: %w", err)
		}
		isAllowed, err := git_model.IsUserAllowedToControlTag(ctx, protectedTags, rel.TagName, rel.PublisherID)
		if err != nil {
			return err
		}
		if !isAllowed {
			return models.ErrProtectedTagName{
				TagName: rel.TagName,
			}
		}

		if stdout, _, err := git.NewCommand(ctx, "tag", "-d").AddDashesAndList(rel.TagName).
			SetDescription(fmt.Sprintf("DeleteReleaseByID (git tag -d): %d", rel.ID)).
			RunStdString(&git.RunOpts{Dir: repo.RepoPath()}); err != nil && !strings.Contains(err.Error(), "not found") {
			log.Error("DeleteReleaseByID (git tag -d): %d in %v Failed:\nStdout: %s\nError: %v", rel.ID, repo, stdout, err)
			return fmt.Errorf("git tag -d: %w", err)
		}

		refName := git.RefNameFromTag(rel.TagName)
		notify_service.PushCommits(
			ctx, doer, repo,
			&repository.PushUpdateOptions{
				RefFullName: refName,
				OldCommitID: rel.Sha1,
				NewCommitID: git.EmptySHA,
			}, repository.NewPushCommits())
		notify_service.DeleteRef(ctx, doer, repo, refName)

		if err := repo_model.DeleteReleaseByID(ctx, rel.ID); err != nil {
			return fmt.Errorf("DeleteReleaseByID: %w", err)
		}
	} else {
		rel.IsTag = true

		if err := repo_model.UpdateRelease(ctx, rel); err != nil {
			return fmt.Errorf("Update: %w", err)
		}
	}

	rel.Repo = repo
	if err := rel.LoadAttributes(ctx); err != nil {
		return fmt.Errorf("LoadAttributes: %w", err)
	}

	if err := repo_model.DeleteAttachmentsByRelease(ctx, rel.ID); err != nil {
		return fmt.Errorf("DeleteAttachments: %w", err)
	}

	for i := range rel.Attachments {
		attachment := rel.Attachments[i]
		if err := storage.Attachments.Delete(attachment.RelativePath()); err != nil {
			log.Error("Delete attachment %s of release %s failed: %v", attachment.UUID, rel.ID, err)
		}
	}

	notify_service.DeleteRelease(ctx, doer, rel)

	return nil
}
