import { getClientUser } from "@/utils/client";
import { useAppSelector } from "@/utils/hooks";
import * as React from "react";

import {
  ListNamespaceOptions,
  ListServiceOptions,
  Service_Spec_Type,
} from "@octelium/apis/main/userv1";
import { useQuery } from "@tanstack/react-query";

import CopyText from "@/components/CopyText";
import EmptyList from "@/components/EmptyList";
import InfoItem from "@/components/InfoItem";
import Paginator from "@/components/Paginator";
import {
  ResourceListItem,
  ResourceListLabel,
  ResourceListWrapper,
} from "@/components/ResourceList";
import { getDomain, printResourceNameWithDisplay, toNumOrZero } from "@/utils";
import { Service, ServiceList } from "@octelium/apis/main/userv1";
import { BiLinkExternal } from "react-icons/bi";
import { useNavigate, useSearchParams } from "react-router-dom";
import { twMerge } from "tailwind-merge";
import { match } from "ts-pattern";

import { getServicePrivateFQDN, getServicePublicFQDN } from "@/utils/octelium";

import { BiLogoPostgresql } from "react-icons/bi";
import { HiMiniCommandLine } from "react-icons/hi2";
import { SiKubernetes, SiMysql } from "react-icons/si";

import parseQuery from "@/utils/parseQuery";
import { Collapse, Text } from "@mantine/core";
import { IoIosDesktop } from "react-icons/io";
import ConnectCommand from "./ConnectCommand";

import { motion, useReducedMotion } from "framer-motion";

import { Namespace } from "@octelium/apis/main/userv1";

const getTypeIcon = (svc: Service) => {
  return match(svc.spec?.type)
    .with(Service_Spec_Type.KUBERNETES, () => <SiKubernetes />)
    .with(Service_Spec_Type.MYSQL, () => <SiMysql />)
    .with(Service_Spec_Type.POSTGRES, () => <BiLogoPostgresql />)
    .with(Service_Spec_Type.SSH, () => <HiMiniCommandLine />)
    .with(Service_Spec_Type.WEB, () => <IoIosDesktop />)
    .otherwise(() => <TypeText name={getType(svc)} />);
};

const TypeText = (props: { name: string }) => {
  return (
    <span className="font-extrabold text-xs md:text-lg">{props.name}</span>
  );
};

const getType = (svc: Service): string => {
  return match(svc.spec?.type)
    .with(Service_Spec_Type.GRPC, () => "gRPC")
    .with(Service_Spec_Type.HTTP, () => "HTTP")
    .with(Service_Spec_Type.KUBERNETES, () => "Kubernetes")
    .with(Service_Spec_Type.MYSQL, () => "MySQL")
    .with(Service_Spec_Type.POSTGRES, () => "PostgreSQL")
    .with(Service_Spec_Type.SSH, () => "SSH")
    .with(Service_Spec_Type.TCP, () => "TCP")
    .with(Service_Spec_Type.UDP, () => "UDP")
    .with(Service_Spec_Type.WEB, () => "Web App")
    .with(Service_Spec_Type.DNS, () => "DNS")
    .otherwise(() => "");
};

const SvcLabel = (props: { children?: React.ReactNode; label?: string }) => {
  return (
    <span
      className={twMerge(
        "p-0 rounded-full font-bold text-xs flex-none mx-1 my-1 flex flex-row flex-shrink",
        "border-[1px] border-gray-400 shadow-md",
      )}
    >
      {props.label && (
        <span
          className={twMerge(
            `bg-gray-800 text-white shadow-lg px-2 py-1 rounded-s-full`,
          )}
        >
          {props.label}
        </span>
      )}
      <span className={twMerge(`px-2 py-1 flex-none flex`)}>
        {props.children}
      </span>
    </span>
  );
};

const ItemDetails = (props: { item: Service; domain: string }) => {
  const { item } = props;
  const md = item.metadata!;

  return (
    <div>
      {md.description && (
        <InfoItem title="Description">{md.description}</InfoItem>
      )}
      <InfoItem title="Private FQDN">
        <CopyText value={getServicePrivateFQDN(item, props.domain)} />
      </InfoItem>
      {item.spec?.isPublic && (
        <InfoItem title="Public FQDN">
          <CopyText value={getServicePublicFQDN(item, props.domain)} />
        </InfoItem>
      )}
      {item.status?.addresses && item.status.addresses.length > 0 && (
        <InfoItem title="Private Addresses">
          <div className="flex flex-col">
            {item.status?.addresses.map((x) => (
              <span className="w-full" key={x}>
                <CopyText value={x} />
              </span>
            ))}
          </div>
        </InfoItem>
      )}

      <ConnectCommand service={props.item} domain={props.domain} />
    </div>
  );
};

const Item = (props: { item: Service; domain: string; skipNS?: boolean }) => {
  const { item } = props;

  const md = item.metadata!;

  let [showDetails, setShowDetails] = React.useState(false);

  return (
    <div
      className="font-semibold w-full"
      onMouseEnter={() => {
        setShowDetails(true);
      }}
      onMouseLeave={() => {
        setShowDetails(false);
      }}
    >
      <div className="flex items-start">
        <div className="w-[40px] h-[40px] md:w-[60px] md:h-[60px] flex flex-col items-center justify-center md:text-4xl font-extrabold mr-3 bg-zinc-900 text-white p-4 rounded-[50%] shadow-md">
          {getTypeIcon(item)}
        </div>
        <div className="flex flex-col flex-1">
          <div className="flex items-center font-bold">
            <Text className="mr-2 flex flex-row" size="sm" fw={"bold"}>
              <CopyText
                value={item.status?.primaryHostname ?? item.metadata!.name}
              />

              {md.displayName && (
                <Text className="ml-3" c="gray.7" inherit>
                  {md.displayName}
                </Text>
              )}
            </Text>
          </div>
          <div className="w-full mt-1 flex flex-row">
            <ResourceListLabel label="Type">{getType(item)}</ResourceListLabel>
            {!props.skipNS && (
              <ResourceListLabel label="Namespace">
                {" "}
                {item.status?.namespace}
              </ResourceListLabel>
            )}
            <ResourceListLabel label="Port">
              {item.spec?.port}
            </ResourceListLabel>
            {/*
            <SvcLabel label="Namespace"> {item.metadata?.namespace}</SvcLabel>
            <SvcLabel label="Hostname">{getHostName(item)}</SvcLabel>
            */}
            {item.spec?.isTLS && <ResourceListLabel>TLS</ResourceListLabel>}
          </div>

          <Collapse in={showDetails} transitionDuration={500}>
            <ItemDetails item={item} domain={props.domain} />
          </Collapse>
        </div>
        <div className="flex items-center justify-center">
          {item.spec?.isPublic && item.spec.type === Service_Spec_Type.WEB && (
            <a
              className={twMerge(
                "bg-gray-800 text-white py-2 px-4 ml-2 font-bold shadow-lg text-sm rounded-lg",
                "hover:bg-black transition-all duration-200 shadow-xl",
                "flex flex-row items-center justify-center",
              )}
              href={`https://${getServicePublicFQDN(item, props.domain)}`}
              target="_blank"
            >
              <span className="px-1">Visit</span>
              <BiLinkExternal />
            </a>
          )}
        </div>
      </div>
    </div>
  );
};

const ServiceListC = (props: { itemsList: ServiceList }) => {
  let [searchParams, _] = useSearchParams();
  const path = searchParams.has("namespace")
    ? `/services?namespace=${searchParams.get("namespace")}`
    : `/services`;

  const domain = getDomain();

  return (
    <div>
      <Paginator meta={props.itemsList.listResponseMeta!} path={path} />

      <ResourceListWrapper>
        {props.itemsList.items.length === 0 && (
          <EmptyList title="No Services Found"></EmptyList>
        )}
        {props.itemsList.items.map((item) => (
          <ResourceListItem key={item.metadata!.uid}>
            <Item
              item={item}
              domain={domain}
              skipNS={searchParams.has("namespace")}
            />
          </ResourceListItem>
        ))}
      </ResourceListWrapper>

      <Paginator meta={props.itemsList.listResponseMeta!} path={path} />
    </div>
  );
};

type Entry = {
  key: string;
  value: string | null;
  label: string;
};

const NamespaceFilter = (props: {
  namespaces: Namespace[];
  active: string | null;
  onSelect: (name: string | null) => void;
}) => {
  const reduced = useReducedMotion();

  const entries: Entry[] = [
    { key: "__all__", value: null, label: "All Namespaces" },
    ...props.namespaces
      .filter((x) => x.metadata!.name !== "octelium")
      .map((x) => ({
        key: x.metadata!.name,
        value: x.metadata!.name,
        label: printResourceNameWithDisplay(x.metadata!),
      })),
  ];

  return (
    <div className="mb-5">
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
        Filter by namespace
      </div>

      <div className="-mx-1 flex gap-1 overflow-x-auto px-1 pb-2 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {entries.map((e) => {
          const isActive = e.value === props.active;

          return (
            <button
              key={e.key}
              type="button"
              onClick={() => props.onSelect(e.value)}
              aria-pressed={isActive}
              className={twMerge(
                "relative cursor-pointer flex-none rounded-full px-3.5 py-1.5 text-sm font-bold whitespace-nowrap transition-colors duration-500",
                isActive
                  ? "text-white"
                  : "text-slate-600 hover:bg-slate-200/70 hover:text-slate-900",
              )}
            >
              {isActive &&
                (reduced ? (
                  <span className="absolute inset-0 rounded-full bg-zinc-900" />
                ) : (
                  <motion.span
                    layoutId="ns-filter-active"
                    className="absolute inset-0 rounded-full bg-zinc-900 shadow-sm"
                    transition={{ type: "spring", stiffness: 400, damping: 32 }}
                  />
                ))}
              <span className="relative font-semibold">{e.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
};

const Page = () => {
  const settings = useAppSelector((state) => state.settings);

  let [searchParams, _] = useSearchParams();
  const page = toNumOrZero(searchParams.get("page"));
  const hasNS = searchParams.has("namespace");
  const navigate = useNavigate();

  let opts = parseQuery<{ common: { page: number; itemsPerPage?: number } }>(
    searchParams.toString(),
  );
  if (opts.common && opts.common.page && opts.common.page > 0) {
    opts.common.page = opts.common.page - 1;
  }

  let o = ListServiceOptions.fromJsonString(JSON.stringify(opts));
  ListServiceOptions.mergePartial(o, {
    common: {
      itemsPerPage: settings.itemsPerPage,
    },
  });

  const qry = useQuery({
    queryKey: ["user/main.listService", ListServiceOptions.toJsonString(o)],
    queryFn: async () => {
      return await getClientUser().listService(o);
    },
  });

  const qryNS = useQuery({
    queryKey: ["user/main.listNamespace", ListServiceOptions.toJsonString(o)],
    queryFn: async () => {
      return await getClientUser().listNamespace(ListNamespaceOptions.create());
    },
  });

  return (
    <>
      <title>Services - Octelium Portal</title>
      <div className="mt-4 mb-6">
        <div
          className={twMerge(
            "font-bold text-3xl text-gray-800 text-shadow-2xs",
          )}
        >
          Services
        </div>
      </div>
      <div>
        {qryNS.isSuccess &&
          qryNS.data &&
          qryNS.data.response.items.length > 0 && (
            <div className="mb-4">
              <NamespaceFilter
                namespaces={qryNS.data.response.items}
                active={searchParams.get("namespace")}
                onSelect={(v) => {
                  navigate(v ? `/services?namespace=${v}` : "/services");
                }}
              />
            </div>
          )}
      </div>
      {qry.isSuccess && qry.data && (
        <ServiceListC itemsList={qry.data.response} />
      )}
    </>
  );
};

export default Page;
