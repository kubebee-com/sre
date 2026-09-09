package cache

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"gocloud.dev/blob"
	_ "gocloud.dev/blob/azureblob"
	_ "gocloud.dev/blob/gcsblob"
	_ "gocloud.dev/blob/s3blob"
	"gocloud.dev/gcerrors"
)

const maxBlobObjectBytes = int64(MaxAllowedValueBytes)*2 + cacheEnvelopeOverhead

// BlobObjectStore adapts the maintained Go Cloud blob abstraction to the
// encrypted RemoteCache contract. Authentication, retries, and TLS remain in
// the selected Go Cloud driver instead of being reimplemented here.
type BlobObjectStore struct {
	bucket *blob.Bucket
}

var _ ObjectStore = (*BlobObjectStore)(nil)

func NewBlobObjectStore(bucket *blob.Bucket) (*BlobObjectStore, error) {
	if bucket == nil {
		return nil, errors.New("blob bucket is required")
	}
	return &BlobObjectStore{bucket: bucket}, nil
}

// OpenBlobObjectStore opens S3 (s3://), GCS (gs://), or Azure Blob
// (azblob://) using the driver's standard credential chain. Insecure driver
// query switches are rejected so callers cannot silently disable TLS.
func OpenBlobObjectStore(ctx context.Context, bucketURL string) (*BlobObjectStore, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	bucketURL = strings.TrimSpace(bucketURL)
	if strings.ContainsAny(bucketURL, "\r\n\x00") {
		return nil, errors.New("object store URL is invalid")
	}
	u, err := url.Parse(bucketURL)
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil || u.Opaque != "" {
		return nil, errors.New("object store URL is invalid")
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		return nil, errors.New("object store URL is invalid")
	}
	switch strings.ToLower(u.Scheme) {
	case "s3", "gs", "azblob":
	default:
		return nil, fmt.Errorf("unsupported object store scheme %q", u.Scheme)
	}
	for key, values := range u.Query() {
		if !isTrueQueryValue(values) {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "insecure", "disable_https", "disablehttps", "skip_tls_verify", "skiptlsverify":
			return nil, errors.New("insecure object store transport options are forbidden")
		}
	}
	bucket, err := blob.OpenBucket(ctx, u.String())
	if err != nil {
		return nil, cacheBackendError(CacheErrorSetup, "open", err)
	}
	return NewBlobObjectStore(bucket)
}

func isTrueQueryValue(values []string) bool {
	for _, value := range values {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
}

// NewS3ObjectStore, NewGCSObjectStore, and NewAzureBlobObjectStore are named
// constructors for callers that open a bucket with provider-specific options.
func NewS3ObjectStore(bucket *blob.Bucket) (*BlobObjectStore, error) {
	return NewBlobObjectStore(bucket)
}

func NewGCSObjectStore(bucket *blob.Bucket) (*BlobObjectStore, error) {
	return NewBlobObjectStore(bucket)
}

func NewAzureBlobObjectStore(bucket *blob.Bucket) (*BlobObjectStore, error) {
	return NewBlobObjectStore(bucket)
}

func (s *BlobObjectStore) Get(ctx context.Context, key string) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateBlobKey(key); err != nil {
		return nil, err
	}
	reader, err := s.bucket.NewReader(ctx, key, nil)
	if err != nil {
		if gcerrors.Code(err) == gcerrors.NotFound {
			return nil, ErrObjectNotFound
		}
		return nil, cacheBackendError(CacheErrorTransport, "read", err)
	}
	defer reader.Close()
	value, err := io.ReadAll(io.LimitReader(reader, maxBlobObjectBytes+1))
	if err != nil {
		return nil, cacheBackendError(CacheErrorTransport, "read", err)
	}
	if int64(len(value)) > maxBlobObjectBytes {
		return nil, ErrCacheValueTooLarge
	}
	return value, nil
}

func (s *BlobObjectStore) Put(ctx context.Context, key string, value []byte, expiresAt time.Time) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateBlobKey(key); err != nil {
		return err
	}
	if int64(len(value)) > maxBlobObjectBytes {
		return ErrCacheValueTooLarge
	}
	if expiresAt.IsZero() {
		return errors.New("object expiration is required")
	}
	metadata := map[string]string{
		"sre-agent-expires-at": expiresAt.UTC().Format(time.RFC3339Nano),
	}
	if err := s.bucket.WriteAll(ctx, key, value, &blob.WriterOptions{
		ContentType: "application/octet-stream",
		Metadata:    metadata,
	}); err != nil {
		return cacheBackendError(CacheErrorTransport, "write", err)
	}
	return nil
}

func (s *BlobObjectStore) Delete(ctx context.Context, key string) error {
	if err := checkContext(ctx); err != nil {
		return err
	}
	if err := validateBlobKey(key); err != nil {
		return err
	}
	if err := s.bucket.Delete(ctx, key); err != nil {
		if gcerrors.Code(err) == gcerrors.NotFound {
			return ErrObjectNotFound
		}
		return cacheBackendError(CacheErrorTransport, "delete", err)
	}
	return nil
}

func (s *BlobObjectStore) List(ctx context.Context, prefix string) ([]RemoteObject, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateBlobPrefix(prefix); err != nil {
		return nil, err
	}
	iterator := s.bucket.List(&blob.ListOptions{Prefix: prefix})
	objects := make([]RemoteObject, 0)
	for {
		object, err := iterator.Next(ctx)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, cacheBackendError(CacheErrorTransport, "list", err)
		}
		if object == nil || object.IsDir || !strings.HasPrefix(object.Key, prefix) {
			continue
		}
		objects = append(objects, RemoteObject{Key: object.Key, Size: object.Size, LastModified: object.ModTime})
		if len(objects) > MaxAllowedEntries {
			return nil, ErrCacheLimit
		}
	}
	return objects, nil
}

func validateBlobKey(key string) error {
	if strings.TrimSpace(key) == "" || strings.ContainsAny(key, "\r\n\x00") || strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		return ErrCacheInvalidKey
	}
	return nil
}

func validateBlobPrefix(prefix string) error {
	if strings.TrimSpace(prefix) == "" || strings.ContainsAny(prefix, "\r\n\x00") || strings.HasPrefix(prefix, "/") || strings.Contains(prefix, "..") {
		return ErrCacheInvalidKey
	}
	return nil
}
